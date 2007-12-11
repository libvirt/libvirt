/*
 * libvir.c: this modules implements the main part of the glue of the
 *           libvir library and the Python interpreter. It provides the
 *           entry points where an automatically generated stub is
 *           unpractical
 *
 * Copyright (C) 2005, 2007 Red Hat, Inc.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include "config.h"

#include <Python.h>
#include "libvirt/libvirt.h"
#include "libvirt/virterror.h"
#include "libvirt_wrap.h"
#include "libvirt-py.h"

#ifndef __CYGWIN__
extern void initlibvirtmod(void);
#else
extern void initcygvirtmod(void);
#endif

PyObject *libvirt_virDomainGetUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args);
PyObject *libvirt_virNetworkGetUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args);
PyObject *libvirt_virGetLastError(PyObject *self ATTRIBUTE_UNUSED, PyObject *args);
PyObject *libvirt_virConnGetLastError(PyObject *self ATTRIBUTE_UNUSED, PyObject *args);
PyObject * libvirt_virDomainBlockStats(PyObject *self ATTRIBUTE_UNUSED, PyObject *args);
PyObject * libvirt_virDomainInterfaceStats(PyObject *self ATTRIBUTE_UNUSED, PyObject *args);
PyObject * libvirt_virNodeGetCellsFreeMemory(PyObject *self ATTRIBUTE_UNUSED, PyObject *args);

/************************************************************************
 *									*
 *		Statistics						*
 *									*
 ************************************************************************/

PyObject *
libvirt_virDomainBlockStats(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    virDomainPtr domain;
    PyObject *pyobj_domain;
    char * path;
    int c_retval;
    virDomainBlockStatsStruct stats;
    PyObject *info;

    if (!PyArg_ParseTuple(args, (char *)"Oz:virDomainBlockStats",
        &pyobj_domain,&path))
	return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    c_retval = virDomainBlockStats(domain, path, &stats, sizeof(stats));
    if (c_retval < 0) {
        Py_INCREF(Py_None);
	return(Py_None);
    }

    /* convert to a Python tupple of long objects */
    info = PyTuple_New(5);
    PyTuple_SetItem(info, 0, PyLong_FromLongLong(stats.rd_req));
    PyTuple_SetItem(info, 1, PyLong_FromLongLong(stats.rd_bytes));
    PyTuple_SetItem(info, 2, PyLong_FromLongLong(stats.wr_req));
    PyTuple_SetItem(info, 3, PyLong_FromLongLong(stats.wr_bytes));
    PyTuple_SetItem(info, 4, PyLong_FromLongLong(stats.errs));
    return(info);
}

PyObject *
libvirt_virDomainInterfaceStats(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    virDomainPtr domain;
    PyObject *pyobj_domain;
    char * path;
    int c_retval;
    virDomainInterfaceStatsStruct stats;
    PyObject *info;

    if (!PyArg_ParseTuple(args, (char *)"Oz:virDomainInterfaceStats",
        &pyobj_domain,&path))
	return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    c_retval = virDomainInterfaceStats(domain, path, &stats, sizeof(stats));
    if (c_retval < 0) {
        Py_INCREF(Py_None);
	return(Py_None);
    }

    /* convert to a Python tupple of long objects */
    info = PyTuple_New(8);
    PyTuple_SetItem(info, 0, PyLong_FromLongLong(stats.rx_bytes));
    PyTuple_SetItem(info, 1, PyLong_FromLongLong(stats.rx_packets));
    PyTuple_SetItem(info, 2, PyLong_FromLongLong(stats.rx_errs));
    PyTuple_SetItem(info, 3, PyLong_FromLongLong(stats.rx_drop));
    PyTuple_SetItem(info, 4, PyLong_FromLongLong(stats.tx_bytes));
    PyTuple_SetItem(info, 5, PyLong_FromLongLong(stats.tx_packets));
    PyTuple_SetItem(info, 6, PyLong_FromLongLong(stats.tx_errs));
    PyTuple_SetItem(info, 7, PyLong_FromLongLong(stats.tx_drop));
    return(info);
}
/************************************************************************
 *									*
 *		Global error handler at the Python level		*
 *									*
 ************************************************************************/

static PyObject *libvirt_virPythonErrorFuncHandler = NULL;
static PyObject *libvirt_virPythonErrorFuncCtxt = NULL;

PyObject *
libvirt_virGetLastError(PyObject *self ATTRIBUTE_UNUSED, PyObject *args ATTRIBUTE_UNUSED)
{
    virError err;
    PyObject *info;

    if (virCopyLastError(&err) <= 0) {
        Py_INCREF(Py_None);
	return(Py_None);
    }

    info = PyTuple_New(9);
    PyTuple_SetItem(info, 0, PyInt_FromLong((long) err.code));
    PyTuple_SetItem(info, 1, PyInt_FromLong((long) err.domain));
    PyTuple_SetItem(info, 2, libvirt_constcharPtrWrap(err.message));
    PyTuple_SetItem(info, 3, PyInt_FromLong((long) err.level));
    PyTuple_SetItem(info, 4, libvirt_constcharPtrWrap(err.str1));
    PyTuple_SetItem(info, 5, libvirt_constcharPtrWrap(err.str2));
    PyTuple_SetItem(info, 6, libvirt_constcharPtrWrap(err.str3));
    PyTuple_SetItem(info, 7, PyInt_FromLong((long) err.int1));
    PyTuple_SetItem(info, 8, PyInt_FromLong((long) err.int2));

    return info;
}

PyObject *
libvirt_virConnGetLastError(PyObject *self ATTRIBUTE_UNUSED, PyObject *args)
{
    virError err;
    PyObject *info;
    virConnectPtr conn;
    PyObject *pyobj_conn;

    if (!PyArg_ParseTuple(args, (char *)"O:virConGetLastError", &pyobj_conn))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    if (virConnCopyLastError(conn, &err) <= 0) {
        Py_INCREF(Py_None);
	return(Py_None);
    }

    info = PyTuple_New(9);
    PyTuple_SetItem(info, 0, PyInt_FromLong((long) err.code));
    PyTuple_SetItem(info, 1, PyInt_FromLong((long) err.domain));
    PyTuple_SetItem(info, 2, libvirt_constcharPtrWrap(err.message));
    PyTuple_SetItem(info, 3, PyInt_FromLong((long) err.level));
    PyTuple_SetItem(info, 4, libvirt_constcharPtrWrap(err.str1));
    PyTuple_SetItem(info, 5, libvirt_constcharPtrWrap(err.str2));
    PyTuple_SetItem(info, 6, libvirt_constcharPtrWrap(err.str3));
    PyTuple_SetItem(info, 7, PyInt_FromLong((long) err.int1));
    PyTuple_SetItem(info, 8, PyInt_FromLong((long) err.int2));

    return info;
}

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

    LIBVIRT_ENSURE_THREAD_STATE;

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

    LIBVIRT_RELEASE_THREAD_STATE;
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

static int virConnectCredCallbackWrapper(virConnectCredentialPtr cred,
                                         unsigned int ncred,
                                         void *cbdata) {
    PyObject *list;
    PyObject *pycred;
    PyObject *pyauth = (PyObject *)cbdata;
    PyObject *pycbdata;
    PyObject *pycb;
    PyObject *pyret;
    int ret = -1, i;

    LIBVIRT_ENSURE_THREAD_STATE;

    pycb = PyList_GetItem(pyauth, 1);
    pycbdata = PyList_GetItem(pyauth, 2);

    list = PyTuple_New(2);
    pycred = PyTuple_New(ncred);
    for (i = 0 ; i < ncred ; i++) {
        PyObject *pycreditem;
        pycreditem = PyList_New(5);
        Py_INCREF(Py_None);
        PyTuple_SetItem(pycred, i, pycreditem);
        PyList_SetItem(pycreditem, 0, PyInt_FromLong((long) cred[i].type));
        PyList_SetItem(pycreditem, 1, PyString_FromString(cred[i].prompt));
        if (cred[i].challenge) {
            PyList_SetItem(pycreditem, 2, PyString_FromString(cred[i].challenge));
        } else {
            Py_INCREF(Py_None);
            PyList_SetItem(pycreditem, 2, Py_None);
        }
        if (cred[i].defresult) {
            PyList_SetItem(pycreditem, 3, PyString_FromString(cred[i].defresult));
        } else {
            Py_INCREF(Py_None);
            PyList_SetItem(pycreditem, 3, Py_None);
        }
        PyList_SetItem(pycreditem, 4, Py_None);
    }

    PyTuple_SetItem(list, 0, pycred);
    Py_XINCREF(pycbdata);
    PyTuple_SetItem(list, 1, pycbdata);

    PyErr_Clear();
    pyret = PyEval_CallObject(pycb, list);
    if (PyErr_Occurred())
        goto cleanup;

    ret = PyLong_AsLong(pyret);
    if (ret == 0) {
        for (i = 0 ; i < ncred ; i++) {
            PyObject *pycreditem;
            PyObject *pyresult;
            char *result = NULL;
            pycreditem = PyTuple_GetItem(pycred, i);
            pyresult = PyList_GetItem(pycreditem, 4);
            if (pyresult != Py_None)
                result = PyString_AsString(pyresult);
            if (result != NULL) {
                cred[i].result = strdup(result);
                cred[i].resultlen = strlen(result);
            } else {
                cred[i].result = NULL;
                cred[i].resultlen = 0;
            }
        }
    }

 cleanup:
    Py_XDECREF(list);
    Py_XDECREF(pyret);

    LIBVIRT_RELEASE_THREAD_STATE;

    return ret;
}


static PyObject *
libvirt_virConnectOpenAuth(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    virConnectPtr c_retval;
    char * name;
    int flags;
    PyObject *pyauth;
    PyObject *pycredcb;
    PyObject *pycredtype;
    virConnectAuth auth;

    if (!PyArg_ParseTuple(args, (char *)"zOi:virConnectOpenAuth", &name, &pyauth, &flags))
        return(NULL);

    pycredtype = PyList_GetItem(pyauth, 0);
    pycredcb = PyList_GetItem(pyauth, 1);

    auth.ncredtype = PyList_Size(pycredtype);
    if (auth.ncredtype) {
        int i;
        auth.credtype = malloc(sizeof(*auth.credtype) * auth.ncredtype);
        if (auth.credtype == NULL) {
            Py_INCREF(Py_None);
            return (Py_None);
        }
        for (i = 0 ; i < auth.ncredtype ; i++) {
            PyObject *val;
            val = PyList_GetItem(pycredtype, i);
            auth.credtype[i] = (int)PyLong_AsLong(val);
        }
    }
    auth.cb = pycredcb ? virConnectCredCallbackWrapper : NULL;
    auth.cbdata = pyauth;

    LIBVIRT_BEGIN_ALLOW_THREADS;

    c_retval = virConnectOpenAuth(name, &auth, flags);
    LIBVIRT_END_ALLOW_THREADS;
    py_retval = libvirt_virConnectPtrWrap((virConnectPtr) c_retval);
    return(py_retval);
}


/************************************************************************
 *									*
 *		Wrappers for functions where generator fails		*
 *									*
 ************************************************************************/

static PyObject *
libvirt_virGetVersion (PyObject *self ATTRIBUTE_UNUSED, PyObject *args)
{
    char *type = NULL;
    unsigned long libVer, typeVer = 0;
    int c_retval;

    if (!PyArg_ParseTuple (args, (char *) "|s", &type))
        return NULL;

    LIBVIRT_BEGIN_ALLOW_THREADS;

    if (type == NULL)
        c_retval = virGetVersion (&libVer, NULL, NULL);
    else
        c_retval = virGetVersion (&libVer, type, &typeVer);

    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval == -1) {
        Py_INCREF(Py_None);
        return (Py_None);
    }

    if (type == NULL)
        return PyInt_FromLong (libVer);
    else
        return Py_BuildValue ((char *) "kk", libVer, typeVer);
}

static PyObject *
libvirt_virDomainFree(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval;
    virDomainPtr domain;
    PyObject *pyobj_domain;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainFree", &pyobj_domain))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virDomainFree(domain);
    LIBVIRT_END_ALLOW_THREADS;
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

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virConnectClose(conn);
    LIBVIRT_END_ALLOW_THREADS;
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

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virConnectListDomains(conn, &ids[0], 500);
    LIBVIRT_END_ALLOW_THREADS;
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
libvirt_virConnectListDefinedDomains(PyObject *self ATTRIBUTE_UNUSED,
				     PyObject *args) {
    PyObject *py_retval;
    char **names = NULL;
    int c_retval, i;
    virConnectPtr conn;
    PyObject *pyobj_conn;


    if (!PyArg_ParseTuple(args, (char *)"O:virConnectListDefinedDomains", &pyobj_conn))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    c_retval = virConnectNumOfDefinedDomains(conn);
    if (c_retval < 0) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    
    if (c_retval) {
        names = malloc(sizeof(*names) * c_retval);
        if (!names) {
            Py_INCREF(Py_None);
            return (Py_None);
        }
        c_retval = virConnectListDefinedDomains(conn, names, c_retval);
        if (c_retval < 0) {
            free(names);
            Py_INCREF(Py_None);
            return(Py_None);
        }
    }
    py_retval = PyList_New(c_retval);

    if (names) {
        for (i = 0;i < c_retval;i++) {
            PyList_SetItem(py_retval, i, libvirt_constcharPtrWrap(names[i]));
            free(names[i]);
        }
        free(names);
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

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virDomainGetInfo(domain, &info);
    LIBVIRT_END_ALLOW_THREADS;
    if (c_retval < 0) {
        Py_INCREF(Py_None);
	return(Py_None);
    }
    py_retval = PyList_New(5);
    PyList_SetItem(py_retval, 0, libvirt_intWrap((int) info.state));
    PyList_SetItem(py_retval, 1, libvirt_ulongWrap(info.maxMem));
    PyList_SetItem(py_retval, 2, libvirt_ulongWrap(info.memory));
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

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virNodeGetInfo(conn, &info);
    LIBVIRT_END_ALLOW_THREADS;
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
    unsigned char uuid[VIR_UUID_BUFLEN];
    virDomainPtr domain;
    PyObject *pyobj_domain;
    int c_retval;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainGetUUID", &pyobj_domain))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    if (domain == NULL) {
        Py_INCREF(Py_None);
	return(Py_None);
    }
    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virDomainGetUUID(domain, &uuid[0]);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0) {
        Py_INCREF(Py_None);
	return(Py_None);
    }
    py_retval = PyString_FromStringAndSize((char *) &uuid[0], VIR_UUID_BUFLEN);

    return(py_retval);
}

static PyObject *
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

    if ((uuid == NULL) || (len != VIR_UUID_BUFLEN)) {
        Py_INCREF(Py_None);
	return(Py_None);
    }

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virDomainLookupByUUID(conn, uuid);
    LIBVIRT_END_ALLOW_THREADS;
    py_retval = libvirt_virDomainPtrWrap((virDomainPtr) c_retval);
    return(py_retval);
}


static PyObject *
libvirt_virNetworkFree(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval;
    virNetworkPtr domain;
    PyObject *pyobj_domain;

    if (!PyArg_ParseTuple(args, (char *)"O:virNetworkFree", &pyobj_domain))
        return(NULL);
    domain = (virNetworkPtr) PyvirNetwork_Get(pyobj_domain);

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virNetworkFree(domain);
    LIBVIRT_END_ALLOW_THREADS;
    py_retval = libvirt_intWrap((int) c_retval);
    return(py_retval);
}


static PyObject *
libvirt_virConnectListNetworks(PyObject *self ATTRIBUTE_UNUSED,
			       PyObject *args) {
    PyObject *py_retval;
    char **names = NULL;
    int c_retval, i;
    virConnectPtr conn;
    PyObject *pyobj_conn;


    if (!PyArg_ParseTuple(args, (char *)"O:virConnectListNetworks", &pyobj_conn))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    c_retval = virConnectNumOfNetworks(conn);
    if (c_retval < 0) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    
    if (c_retval) {
        names = malloc(sizeof(*names) * c_retval);
        if (!names) {
            Py_INCREF(Py_None);
            return (Py_None);
        }
        c_retval = virConnectListNetworks(conn, names, c_retval);
        if (c_retval < 0) {
            free(names);
            Py_INCREF(Py_None);
            return(Py_None);
        }
    }
    py_retval = PyList_New(c_retval);

    if (names) {
        for (i = 0;i < c_retval;i++) {
            PyList_SetItem(py_retval, i, libvirt_constcharPtrWrap(names[i]));
            free(names[i]);
        }
        free(names);
    }

    return(py_retval);
}


static PyObject *
libvirt_virConnectListDefinedNetworks(PyObject *self ATTRIBUTE_UNUSED,
				      PyObject *args) {
    PyObject *py_retval;
    char **names = NULL;
    int c_retval, i;
    virConnectPtr conn;
    PyObject *pyobj_conn;


    if (!PyArg_ParseTuple(args, (char *)"O:virConnectListDefinedNetworks", &pyobj_conn))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    c_retval = virConnectNumOfDefinedNetworks(conn);
    if (c_retval < 0) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    
    if (c_retval) {
        names = malloc(sizeof(*names) * c_retval);
        if (!names) {
            Py_INCREF(Py_None);
            return (Py_None);
        }
        c_retval = virConnectListDefinedNetworks(conn, names, c_retval);
        if (c_retval < 0) {
            free(names);
            Py_INCREF(Py_None);
            return(Py_None);
        }
    }
    py_retval = PyList_New(c_retval);

    if (names) {
        for (i = 0;i < c_retval;i++) {
            PyList_SetItem(py_retval, i, libvirt_constcharPtrWrap(names[i]));
            free(names[i]);
        }
        free(names);
    }

    return(py_retval);
}


PyObject *
libvirt_virNetworkGetUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    unsigned char uuid[VIR_UUID_BUFLEN];
    virNetworkPtr domain;
    PyObject *pyobj_domain;
    int c_retval;

    if (!PyArg_ParseTuple(args, (char *)"O:virNetworkGetUUID", &pyobj_domain))
        return(NULL);
    domain = (virNetworkPtr) PyvirNetwork_Get(pyobj_domain);

    if (domain == NULL) {
        Py_INCREF(Py_None);
	return(Py_None);
    }
    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virNetworkGetUUID(domain, &uuid[0]);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0) {
        Py_INCREF(Py_None);
	return(Py_None);
    }
    py_retval = PyString_FromStringAndSize((char *) &uuid[0], VIR_UUID_BUFLEN);

    return(py_retval);
}

static PyObject *
libvirt_virNetworkLookupByUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    virNetworkPtr c_retval;
    virConnectPtr conn;
    PyObject *pyobj_conn;
    unsigned char * uuid;
    int len;

    if (!PyArg_ParseTuple(args, (char *)"Oz#:virNetworkLookupByUUID", &pyobj_conn, &uuid, &len))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    if ((uuid == NULL) || (len != VIR_UUID_BUFLEN)) {
        Py_INCREF(Py_None);
	return(Py_None);
    }

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virNetworkLookupByUUID(conn, uuid);
    LIBVIRT_END_ALLOW_THREADS;
    py_retval = libvirt_virNetworkPtrWrap((virNetworkPtr) c_retval);
    return(py_retval);
}


PyObject *
libvirt_virDomainGetAutostart(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval, autostart;
    virDomainPtr domain;
    PyObject *pyobj_domain;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainGetAutostart", &pyobj_domain))
        return(NULL);

    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virDomainGetAutostart(domain, &autostart);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0) {
        Py_INCREF(Py_None);
	return Py_None;
    }
    py_retval = libvirt_intWrap(autostart);
    return(py_retval);
}


PyObject *
libvirt_virNetworkGetAutostart(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval, autostart;
    virNetworkPtr network;
    PyObject *pyobj_network;

    if (!PyArg_ParseTuple(args, (char *)"O:virNetworkGetAutostart", &pyobj_network))
        return(NULL);

    network = (virNetworkPtr) PyvirNetwork_Get(pyobj_network);

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virNetworkGetAutostart(network, &autostart);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0) {
        Py_INCREF(Py_None);
	return Py_None;
    }
    py_retval = libvirt_intWrap(autostart);
    return(py_retval);
}

PyObject * libvirt_virNodeGetCellsFreeMemory(PyObject *self ATTRIBUTE_UNUSED,
         PyObject *args)
{
    PyObject *py_retval;
    PyObject *pyobj_conn;
    int startCell, maxCells, c_retval, i;
    virConnectPtr conn;
    unsigned long long *freeMems;

    if (!PyArg_ParseTuple(args, (char *)"Oii:virNodeGetCellsFreeMemory", &pyobj_conn, &startCell, &maxCells))
        return(NULL);

    if ((startCell < 0) || (maxCells <= 0) || (startCell + maxCells > 10000))
        goto error;

    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);
    freeMems =
        malloc(maxCells * sizeof(*freeMems));
    if (freeMems == NULL)
        goto error;

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virNodeGetCellsFreeMemory(conn, freeMems, startCell, maxCells);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0) {
	free(freeMems);
error:
        Py_INCREF(Py_None);
	return Py_None;
    }
    py_retval = PyList_New(c_retval);
    for (i = 0;i < c_retval;i++) {
	PyList_SetItem(py_retval, i, 
	        libvirt_longlongWrap((long long) freeMems[i]));
    }
    free(freeMems);
    return(py_retval);
}

/************************************************************************
 *									*
 *			The registration stuff				*
 *									*
 ************************************************************************/
static PyMethodDef libvirtMethods[] = {
#include "libvirt-export.c"
    {(char *) "virGetVersion", libvirt_virGetVersion, METH_VARARGS, NULL},
    {(char *) "virDomainFree", libvirt_virDomainFree, METH_VARARGS, NULL},
    {(char *) "virConnectOpenAuth", libvirt_virConnectOpenAuth, METH_VARARGS, NULL},
    {(char *) "virConnectClose", libvirt_virConnectClose, METH_VARARGS, NULL},
    {(char *) "virConnectListDomainsID", libvirt_virConnectListDomainsID, METH_VARARGS, NULL},
    {(char *) "virConnectListDefinedDomains", libvirt_virConnectListDefinedDomains, METH_VARARGS, NULL},
    {(char *) "virDomainGetInfo", libvirt_virDomainGetInfo, METH_VARARGS, NULL},
    {(char *) "virNodeGetInfo", libvirt_virNodeGetInfo, METH_VARARGS, NULL},
    {(char *) "virDomainGetUUID", libvirt_virDomainGetUUID, METH_VARARGS, NULL},
    {(char *) "virDomainLookupByUUID", libvirt_virDomainLookupByUUID, METH_VARARGS, NULL},
    {(char *) "virRegisterErrorHandler", libvirt_virRegisterErrorHandler, METH_VARARGS, NULL},
    {(char *) "virGetLastError", libvirt_virGetLastError, METH_VARARGS, NULL},
    {(char *) "virConnGetLastError", libvirt_virConnGetLastError, METH_VARARGS, NULL},
    {(char *) "virNetworkFree", libvirt_virNetworkFree, METH_VARARGS, NULL},
    {(char *) "virConnectListNetworks", libvirt_virConnectListNetworks, METH_VARARGS, NULL},
    {(char *) "virConnectListDefinedNetworks", libvirt_virConnectListDefinedNetworks, METH_VARARGS, NULL},
    {(char *) "virNetworkGetUUID", libvirt_virNetworkGetUUID, METH_VARARGS, NULL},
    {(char *) "virNetworkLookupByUUID", libvirt_virNetworkLookupByUUID, METH_VARARGS, NULL},
    {(char *) "virDomainGetAutostart", libvirt_virDomainGetAutostart, METH_VARARGS, NULL},
    {(char *) "virNetworkGetAutostart", libvirt_virNetworkGetAutostart, METH_VARARGS, NULL},
    {(char *) "virDomainBlockStats", libvirt_virDomainBlockStats, METH_VARARGS, NULL},
    {(char *) "virDomainInterfaceStats", libvirt_virDomainInterfaceStats, METH_VARARGS, NULL},
    {(char *) "virNodeGetCellsFreeMemory", libvirt_virNodeGetCellsFreeMemory, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

void
#ifndef __CYGWIN__
initlibvirtmod
#else
initcygvirtmod
#endif
  (void)
{
    static int initialized = 0;

    if (initialized != 0)
        return;

    virInitialize();

    /* intialize the python extension module */
    Py_InitModule((char *)
#ifndef __CYGWIN__
                  "libvirtmod"
#else
                  "cygvirtmod"
#endif
                  , libvirtMethods);

    initialized = 1;
}

/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
