/*
 * libvir.c: this modules implements the main part of the glue of the
 *           libvir library and the Python interpreter. It provides the
 *           entry points where an automatically generated stub is
 *           unpractical
 *
 * Copyright (C) 2005, 2007-2009 Red Hat, Inc.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

/* Horrible kludge to work around even more horrible name-space pollution
   via Python.h.  That file includes /usr/include/python2.5/pyconfig*.h,
   which has over 180 autoconf-style HAVE_* definitions.  Shame on them.  */
#undef HAVE_PTHREAD_H

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

/* The two-statement sequence "Py_INCREF(Py_None); return Py_None;"
   is so common that we encapsulate it here.  Now, each use is simply
   return VIR_PY_NONE;  */
#define VIR_PY_NONE (Py_INCREF (Py_None), Py_None)
#define VIR_PY_INT_FAIL (libvirt_intWrap(-1))
#define VIR_PY_INT_SUCCESS (libvirt_intWrap(0))

static char *py_str(PyObject *obj)
{
    PyObject *str = PyObject_Str(obj);
    if (!str) {
        PyErr_Print();
        PyErr_Clear();
        return NULL;
    };
    return PyString_AsString(str);
}


/************************************************************************
 *									*
 *		Statistics						*
 *									*
 ************************************************************************/

static PyObject *
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
    if (c_retval < 0)
        return VIR_PY_NONE;

    /* convert to a Python tuple of long objects */
    if ((info = PyTuple_New(5)) == NULL)
        return VIR_PY_NONE;
    PyTuple_SetItem(info, 0, PyLong_FromLongLong(stats.rd_req));
    PyTuple_SetItem(info, 1, PyLong_FromLongLong(stats.rd_bytes));
    PyTuple_SetItem(info, 2, PyLong_FromLongLong(stats.wr_req));
    PyTuple_SetItem(info, 3, PyLong_FromLongLong(stats.wr_bytes));
    PyTuple_SetItem(info, 4, PyLong_FromLongLong(stats.errs));
    return(info);
}

static PyObject *
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
    if (c_retval < 0)
        return VIR_PY_NONE;

    /* convert to a Python tuple of long objects */
    if ((info = PyTuple_New(8)) == NULL)
        return VIR_PY_NONE;
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


static PyObject *
libvirt_virDomainGetSchedulerType(PyObject *self ATTRIBUTE_UNUSED,
                                  PyObject *args) {
    virDomainPtr domain;
    PyObject *pyobj_domain, *info;
    char *c_retval;
    int nparams;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainGetScedulerType",
                          &pyobj_domain))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    c_retval = virDomainGetSchedulerType(domain, &nparams);
    if (c_retval == NULL)
        return VIR_PY_NONE;

    /* convert to a Python tuple of long objects */
    if ((info = PyTuple_New(2)) == NULL) {
        free(c_retval);
        return VIR_PY_NONE;
    }

    PyTuple_SetItem(info, 0, libvirt_constcharPtrWrap(c_retval));
    PyTuple_SetItem(info, 1, PyInt_FromLong((long)nparams));
    free(c_retval);
    return(info);
}

static PyObject *
libvirt_virDomainGetSchedulerParameters(PyObject *self ATTRIBUTE_UNUSED,
                                        PyObject *args) {
    virDomainPtr domain;
    PyObject *pyobj_domain, *info;
    char *c_retval;
    int nparams, i;
    virSchedParameterPtr params;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainGetScedulerParameters",
                          &pyobj_domain))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    c_retval = virDomainGetSchedulerType(domain, &nparams);
    if (c_retval == NULL)
        return VIR_PY_NONE;
    free(c_retval);

    if ((params = malloc(sizeof(*params)*nparams)) == NULL)
        return VIR_PY_NONE;

    if (virDomainGetSchedulerParameters(domain, params, &nparams) < 0) {
        free(params);
        return VIR_PY_NONE;
    }

    /* convert to a Python tuple of long objects */
    if ((info = PyDict_New()) == NULL) {
        free(params);
        return VIR_PY_NONE;
    }
    for (i = 0 ; i < nparams ; i++) {
        PyObject *key, *val;

        switch (params[i].type) {
        case VIR_DOMAIN_SCHED_FIELD_INT:
            val = PyInt_FromLong((long)params[i].value.i);
            break;

        case VIR_DOMAIN_SCHED_FIELD_UINT:
            val = PyInt_FromLong((long)params[i].value.ui);
            break;

        case VIR_DOMAIN_SCHED_FIELD_LLONG:
            val = PyLong_FromLongLong((long long)params[i].value.l);
            break;

        case VIR_DOMAIN_SCHED_FIELD_ULLONG:
            val = PyLong_FromLongLong((long long)params[i].value.ul);
            break;

        case VIR_DOMAIN_SCHED_FIELD_DOUBLE:
            val = PyFloat_FromDouble((double)params[i].value.d);
            break;

        case VIR_DOMAIN_SCHED_FIELD_BOOLEAN:
            val = PyBool_FromLong((long)params[i].value.b);
            break;

        default:
            free(params);
            Py_DECREF(info);
            return VIR_PY_NONE;
        }

        key = libvirt_constcharPtrWrap(params[i].field);
        PyDict_SetItem(info, key, val);
    }
    free(params);
    return(info);
}

static PyObject *
libvirt_virDomainSetSchedulerParameters(PyObject *self ATTRIBUTE_UNUSED,
                                        PyObject *args) {
    virDomainPtr domain;
    PyObject *pyobj_domain, *info;
    char *c_retval;
    int nparams, i;
    virSchedParameterPtr params;

    if (!PyArg_ParseTuple(args, (char *)"OO:virDomainSetScedulerParameters",
                          &pyobj_domain, &info))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    c_retval = virDomainGetSchedulerType(domain, &nparams);
    if (c_retval == NULL)
        return VIR_PY_INT_FAIL;
    free(c_retval);

    if ((params = malloc(sizeof(*params)*nparams)) == NULL)
        return VIR_PY_INT_FAIL;

    if (virDomainGetSchedulerParameters(domain, params, &nparams) < 0) {
        free(params);
        return VIR_PY_INT_FAIL;
    }

    /* convert to a Python tuple of long objects */
    for (i = 0 ; i < nparams ; i++) {
        PyObject *key, *val;
        key = libvirt_constcharPtrWrap(params[i].field);
        val = PyDict_GetItem(info, key);
        Py_DECREF(key);

        if (val == NULL)
            continue;

        switch (params[i].type) {
        case VIR_DOMAIN_SCHED_FIELD_INT:
            params[i].value.i = (int)PyInt_AS_LONG(val);
            break;

        case VIR_DOMAIN_SCHED_FIELD_UINT:
            params[i].value.ui = (unsigned int)PyInt_AS_LONG(val);
            break;

        case VIR_DOMAIN_SCHED_FIELD_LLONG:
            params[i].value.l = (long long)PyLong_AsLongLong(val);
            break;

        case VIR_DOMAIN_SCHED_FIELD_ULLONG:
            params[i].value.ul = (unsigned long long)PyLong_AsLongLong(val);
            break;

        case VIR_DOMAIN_SCHED_FIELD_DOUBLE:
            params[i].value.d = (double)PyFloat_AsDouble(val);
            break;

        case VIR_DOMAIN_SCHED_FIELD_BOOLEAN:
            {
                /* Hack - Python's definition of Py_True breaks strict
                 * aliasing rules, so can't directly compare :-(
                 */
                PyObject *hacktrue = PyBool_FromLong(1);
                params[i].value.b = hacktrue == val ? 1 : 0;
                Py_DECREF(hacktrue);
            }
            break;

        default:
            free(params);
            return VIR_PY_INT_FAIL;
        }
    }

    if (virDomainSetSchedulerParameters(domain, params, nparams) < 0) {
        free(params);
        return VIR_PY_INT_FAIL;
    }

    free(params);
    return VIR_PY_INT_SUCCESS;
}

static PyObject *
libvirt_virDomainGetVcpus(PyObject *self ATTRIBUTE_UNUSED,
                          PyObject *args) {
    virDomainPtr domain;
    PyObject *pyobj_domain, *pyretval = NULL, *pycpuinfo = NULL, *pycpumap = NULL;
    virNodeInfo nodeinfo;
    virDomainInfo dominfo;
    virVcpuInfoPtr cpuinfo = NULL;
    unsigned char *cpumap = NULL;
    int cpumaplen, i;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainGetVcpus",
                          &pyobj_domain))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    if (virNodeGetInfo(virDomainGetConnect(domain), &nodeinfo) != 0)
        return VIR_PY_NONE;

    if (virDomainGetInfo(domain, &dominfo) != 0)
        return VIR_PY_NONE;

    if ((cpuinfo = malloc(sizeof(*cpuinfo)*dominfo.nrVirtCpu)) == NULL)
        return VIR_PY_NONE;

    cpumaplen = VIR_CPU_MAPLEN(VIR_NODEINFO_MAXCPUS(nodeinfo));
    if ((cpumap = malloc(dominfo.nrVirtCpu * cpumaplen)) == NULL)
        goto cleanup;

    if (virDomainGetVcpus(domain,
                          cpuinfo, dominfo.nrVirtCpu,
                          cpumap, cpumaplen) < 0)
        goto cleanup;

    /* convert to a Python tuple of long objects */
    if ((pyretval = PyTuple_New(2)) == NULL)
        goto cleanup;
    if ((pycpuinfo = PyList_New(dominfo.nrVirtCpu)) == NULL)
        goto cleanup;
    if ((pycpumap = PyList_New(dominfo.nrVirtCpu)) == NULL)
        goto cleanup;

    for (i = 0 ; i < dominfo.nrVirtCpu ; i++) {
        PyObject *info = PyTuple_New(4);
        if (info == NULL)
            goto cleanup;
        PyTuple_SetItem(info, 0, PyInt_FromLong((long)cpuinfo[i].number));
        PyTuple_SetItem(info, 1, PyInt_FromLong((long)cpuinfo[i].state));
        PyTuple_SetItem(info, 2, PyLong_FromLongLong((long long)cpuinfo[i].cpuTime));
        PyTuple_SetItem(info, 3, PyInt_FromLong((long)cpuinfo[i].cpu));
        PyList_SetItem(pycpuinfo, i, info);
    }
    for (i = 0 ; i < dominfo.nrVirtCpu ; i++) {
        PyObject *info = PyTuple_New(VIR_NODEINFO_MAXCPUS(nodeinfo));
        int j;
        if (info == NULL)
            goto cleanup;
        for (j = 0 ; j < VIR_NODEINFO_MAXCPUS(nodeinfo) ; j++) {
            PyTuple_SetItem(info, j, PyBool_FromLong(VIR_CPU_USABLE(cpumap, cpumaplen, i, j)));
        }
        PyList_SetItem(pycpumap, i, info);
    }
    PyTuple_SetItem(pyretval, 0, pycpuinfo);
    PyTuple_SetItem(pyretval, 1, pycpumap);

    free(cpuinfo);
    free(cpumap);

    return(pyretval);

 cleanup:
    free(cpuinfo);
    free(cpumap);
    /* NB, Py_DECREF is a badly defined macro, so we require
     * braces here to avoid 'ambiguous else' warnings from
     * the compiler.
     * NB. this comment is true at of time of writing wrt to
     * at least python2.5.
     */
    if (pyretval) { Py_DECREF(pyretval); }
    if (pycpuinfo) { Py_DECREF(pycpuinfo); }
    if (pycpumap) { Py_DECREF(pycpumap); }
    return VIR_PY_NONE;
}


static PyObject *
libvirt_virDomainPinVcpu(PyObject *self ATTRIBUTE_UNUSED,
                         PyObject *args) {
    virDomainPtr domain;
    PyObject *pyobj_domain, *pycpumap, *truth;
    virNodeInfo nodeinfo;
    unsigned char *cpumap;
    int cpumaplen, i, vcpu;

    if (!PyArg_ParseTuple(args, (char *)"OiO:virDomainPinVcpu",
                          &pyobj_domain, &vcpu, &pycpumap))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    if (virNodeGetInfo(virDomainGetConnect(domain), &nodeinfo) != 0)
        return VIR_PY_INT_FAIL;

    cpumaplen = VIR_CPU_MAPLEN(VIR_NODEINFO_MAXCPUS(nodeinfo));
    if ((cpumap = malloc(cpumaplen)) == NULL)
        return VIR_PY_INT_FAIL;
    memset(cpumap, 0, cpumaplen);

    truth = PyBool_FromLong(1);
    for (i = 0 ; i < VIR_NODEINFO_MAXCPUS(nodeinfo) ; i++) {
        PyObject *flag = PyTuple_GetItem(pycpumap, i);
        if (flag == truth)
            VIR_USE_CPU(cpumap, i);
        else
            VIR_UNUSE_CPU(cpumap, i);
    }

    virDomainPinVcpu(domain, vcpu, cpumap, cpumaplen);
    Py_DECREF(truth);
    free(cpumap);

    return VIR_PY_INT_SUCCESS;
}


/************************************************************************
 *									*
 *		Global error handler at the Python level		*
 *									*
 ************************************************************************/

static PyObject *libvirt_virPythonErrorFuncHandler = NULL;
static PyObject *libvirt_virPythonErrorFuncCtxt = NULL;

static PyObject *
libvirt_virGetLastError(PyObject *self ATTRIBUTE_UNUSED, PyObject *args ATTRIBUTE_UNUSED)
{
    virError *err;
    PyObject *info;

    if ((err = virGetLastError()) == NULL)
        return VIR_PY_NONE;

    if ((info = PyTuple_New(9)) == NULL)
        return VIR_PY_NONE;
    PyTuple_SetItem(info, 0, PyInt_FromLong((long) err->code));
    PyTuple_SetItem(info, 1, PyInt_FromLong((long) err->domain));
    PyTuple_SetItem(info, 2, libvirt_constcharPtrWrap(err->message));
    PyTuple_SetItem(info, 3, PyInt_FromLong((long) err->level));
    PyTuple_SetItem(info, 4, libvirt_constcharPtrWrap(err->str1));
    PyTuple_SetItem(info, 5, libvirt_constcharPtrWrap(err->str2));
    PyTuple_SetItem(info, 6, libvirt_constcharPtrWrap(err->str3));
    PyTuple_SetItem(info, 7, PyInt_FromLong((long) err->int1));
    PyTuple_SetItem(info, 8, PyInt_FromLong((long) err->int2));

    return info;
}

static PyObject *
libvirt_virConnGetLastError(PyObject *self ATTRIBUTE_UNUSED, PyObject *args)
{
    virError *err;
    PyObject *info;
    virConnectPtr conn;
    PyObject *pyobj_conn;

    if (!PyArg_ParseTuple(args, (char *)"O:virConGetLastError", &pyobj_conn))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    if ((err = virConnGetLastError(conn)) == NULL)
        return VIR_PY_NONE;

    if ((info = PyTuple_New(9)) == NULL)
        return VIR_PY_NONE;
    PyTuple_SetItem(info, 0, PyInt_FromLong((long) err->code));
    PyTuple_SetItem(info, 1, PyInt_FromLong((long) err->domain));
    PyTuple_SetItem(info, 2, libvirt_constcharPtrWrap(err->message));
    PyTuple_SetItem(info, 3, PyInt_FromLong((long) err->level));
    PyTuple_SetItem(info, 4, libvirt_constcharPtrWrap(err->str1));
    PyTuple_SetItem(info, 5, libvirt_constcharPtrWrap(err->str2));
    PyTuple_SetItem(info, 6, libvirt_constcharPtrWrap(err->str3));
    PyTuple_SetItem(info, 7, PyInt_FromLong((long) err->int1));
    PyTuple_SetItem(info, 8, PyInt_FromLong((long) err->int2));

    return info;
}

static void
libvirt_virErrorFuncHandler(ATTRIBUTE_UNUSED void *ctx, virErrorPtr err)
{
    PyObject *list, *info;
    PyObject *result;

#ifdef DEBUG_ERROR
    printf("libvirt_virErrorFuncHandler(%p, %s, ...) called\n", ctx,
           err->message);
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
        if (auth.credtype == NULL)
            return VIR_PY_NONE;
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

    if (c_retval == -1)
        return VIR_PY_NONE;

    if (type == NULL)
        return PyInt_FromLong (libVer);
    else
        return Py_BuildValue ((char *) "kk", libVer, typeVer);
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
    if (c_retval < 0)
        return VIR_PY_NONE;
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
    if (c_retval < 0)
        return VIR_PY_NONE;

    if (c_retval) {
        names = malloc(sizeof(*names) * c_retval);
        if (!names)
            return VIR_PY_NONE;
        c_retval = virConnectListDefinedDomains(conn, names, c_retval);
        if (c_retval < 0) {
            free(names);
            return VIR_PY_NONE;
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
    if (c_retval < 0)
        return VIR_PY_NONE;
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
    if (c_retval < 0)
        return VIR_PY_NONE;
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

static PyObject *
libvirt_virDomainGetUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    unsigned char uuid[VIR_UUID_BUFLEN];
    virDomainPtr domain;
    PyObject *pyobj_domain;
    int c_retval;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainGetUUID", &pyobj_domain))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    if (domain == NULL)
        return VIR_PY_NONE;
    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virDomainGetUUID(domain, &uuid[0]);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0)
        return VIR_PY_NONE;
    py_retval = PyString_FromStringAndSize((char *) &uuid[0], VIR_UUID_BUFLEN);

    return(py_retval);
}

static PyObject *
libvirt_virDomainGetUUIDString(PyObject *self ATTRIBUTE_UNUSED,
                               PyObject *args) {
    PyObject *py_retval;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainPtr dom;
    PyObject *pyobj_dom;
    int c_retval;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainGetUUIDString",
                          &pyobj_dom))
        return(NULL);
    dom = (virDomainPtr) PyvirDomain_Get(pyobj_dom);

    if (dom == NULL)
        return VIR_PY_NONE;
    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virDomainGetUUIDString(dom, &uuidstr[0]);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0)
        return VIR_PY_NONE;

    py_retval = PyString_FromString((char *) &uuidstr[0]);
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

    if ((uuid == NULL) || (len != VIR_UUID_BUFLEN))
        return VIR_PY_NONE;

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virDomainLookupByUUID(conn, uuid);
    LIBVIRT_END_ALLOW_THREADS;
    py_retval = libvirt_virDomainPtrWrap((virDomainPtr) c_retval);
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
    if (c_retval < 0)
        return VIR_PY_NONE;

    if (c_retval) {
        names = malloc(sizeof(*names) * c_retval);
        if (!names)
            return VIR_PY_NONE;
        c_retval = virConnectListNetworks(conn, names, c_retval);
        if (c_retval < 0) {
            free(names);
            return VIR_PY_NONE;
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
    if (c_retval < 0)
        return VIR_PY_NONE;

    if (c_retval) {
        names = malloc(sizeof(*names) * c_retval);
        if (!names)
            return VIR_PY_NONE;
        c_retval = virConnectListDefinedNetworks(conn, names, c_retval);
        if (c_retval < 0) {
            free(names);
            return VIR_PY_NONE;
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
libvirt_virNetworkGetUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    unsigned char uuid[VIR_UUID_BUFLEN];
    virNetworkPtr domain;
    PyObject *pyobj_domain;
    int c_retval;

    if (!PyArg_ParseTuple(args, (char *)"O:virNetworkGetUUID", &pyobj_domain))
        return(NULL);
    domain = (virNetworkPtr) PyvirNetwork_Get(pyobj_domain);

    if (domain == NULL)
        return VIR_PY_NONE;
    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virNetworkGetUUID(domain, &uuid[0]);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0)
        return VIR_PY_NONE;
    py_retval = PyString_FromStringAndSize((char *) &uuid[0], VIR_UUID_BUFLEN);

    return(py_retval);
}

static PyObject *
libvirt_virNetworkGetUUIDString(PyObject *self ATTRIBUTE_UNUSED,
                                PyObject *args) {
    PyObject *py_retval;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virNetworkPtr net;
    PyObject *pyobj_net;
    int c_retval;

    if (!PyArg_ParseTuple(args, (char *)"O:virNetworkGetUUIDString",
                          &pyobj_net))
        return(NULL);
    net = (virNetworkPtr) PyvirNetwork_Get(pyobj_net);

    if (net == NULL)
        return VIR_PY_NONE;
    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virNetworkGetUUIDString(net, &uuidstr[0]);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0)
        return VIR_PY_NONE;

    py_retval = PyString_FromString((char *) &uuidstr[0]);
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

    if ((uuid == NULL) || (len != VIR_UUID_BUFLEN))
        return VIR_PY_NONE;

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virNetworkLookupByUUID(conn, uuid);
    LIBVIRT_END_ALLOW_THREADS;
    py_retval = libvirt_virNetworkPtrWrap((virNetworkPtr) c_retval);
    return(py_retval);
}


static PyObject *
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

    if (c_retval < 0)
        return VIR_PY_INT_FAIL;
    py_retval = libvirt_intWrap(autostart);
    return(py_retval);
}


static PyObject *
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

    if (c_retval < 0)
        return VIR_PY_INT_FAIL;
    py_retval = libvirt_intWrap(autostart);
    return(py_retval);
}

static PyObject *
libvirt_virNodeGetCellsFreeMemory(PyObject *self ATTRIBUTE_UNUSED, PyObject *args)
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
        return VIR_PY_NONE;
    }
    py_retval = PyList_New(c_retval);
    for (i = 0;i < c_retval;i++) {
        PyList_SetItem(py_retval, i,
                libvirt_longlongWrap((long long) freeMems[i]));
    }
    free(freeMems);
    return(py_retval);
}


static PyObject *
libvirt_virConnectListStoragePools(PyObject *self ATTRIBUTE_UNUSED,
                                   PyObject *args) {
    PyObject *py_retval;
    char **names = NULL;
    int c_retval, i;
    virConnectPtr conn;
    PyObject *pyobj_conn;


    if (!PyArg_ParseTuple(args, (char *)"O:virConnectListStoragePools", &pyobj_conn))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    c_retval = virConnectNumOfStoragePools(conn);
    if (c_retval < 0)
        return VIR_PY_NONE;

    if (c_retval) {
        names = malloc(sizeof(*names) * c_retval);
        if (!names)
            return VIR_PY_NONE;
        c_retval = virConnectListStoragePools(conn, names, c_retval);
        if (c_retval < 0) {
            free(names);
            return VIR_PY_NONE;
        }
    }
    py_retval = PyList_New(c_retval);
    if (py_retval == NULL) {
        if (names) {
            for (i = 0;i < c_retval;i++)
                free(names[i]);
            free(names);
        }
        return VIR_PY_NONE;
    }

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
libvirt_virConnectListDefinedStoragePools(PyObject *self ATTRIBUTE_UNUSED,
                                          PyObject *args) {
    PyObject *py_retval;
    char **names = NULL;
    int c_retval, i;
    virConnectPtr conn;
    PyObject *pyobj_conn;


    if (!PyArg_ParseTuple(args, (char *)"O:virConnectListDefinedStoragePools", &pyobj_conn))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    c_retval = virConnectNumOfDefinedStoragePools(conn);
    if (c_retval < 0)
        return VIR_PY_NONE;

    if (c_retval) {
        names = malloc(sizeof(*names) * c_retval);
        if (!names)
            return VIR_PY_NONE;
        c_retval = virConnectListDefinedStoragePools(conn, names, c_retval);
        if (c_retval < 0) {
            free(names);
            return VIR_PY_NONE;
        }
    }
    py_retval = PyList_New(c_retval);
    if (py_retval == NULL) {
        if (names) {
            for (i = 0;i < c_retval;i++)
                free(names[i]);
            free(names);
        }
        return VIR_PY_NONE;
    }

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
libvirt_virStoragePoolListVolumes(PyObject *self ATTRIBUTE_UNUSED,
                                  PyObject *args) {
    PyObject *py_retval;
    char **names = NULL;
    int c_retval, i;
    virStoragePoolPtr pool;
    PyObject *pyobj_pool;


    if (!PyArg_ParseTuple(args, (char *)"O:virStoragePoolListVolumes", &pyobj_pool))
        return(NULL);
    pool = (virStoragePoolPtr) PyvirStoragePool_Get(pyobj_pool);

    c_retval = virStoragePoolNumOfVolumes(pool);
    if (c_retval < 0)
        return VIR_PY_NONE;

    if (c_retval) {
        names = malloc(sizeof(*names) * c_retval);
        if (!names)
            return VIR_PY_NONE;
        c_retval = virStoragePoolListVolumes(pool, names, c_retval);
        if (c_retval < 0) {
            free(names);
            return VIR_PY_NONE;
        }
    }
    py_retval = PyList_New(c_retval);
    if (py_retval == NULL) {
        if (names) {
            for (i = 0;i < c_retval;i++)
                free(names[i]);
            free(names);
        }
        return VIR_PY_NONE;
    }

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
libvirt_virStoragePoolGetAutostart(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval, autostart;
    virStoragePoolPtr pool;
    PyObject *pyobj_pool;

    if (!PyArg_ParseTuple(args, (char *)"O:virStoragePoolGetAutostart", &pyobj_pool))
        return(NULL);

    pool = (virStoragePoolPtr) PyvirStoragePool_Get(pyobj_pool);

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virStoragePoolGetAutostart(pool, &autostart);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0)
        return VIR_PY_NONE;

    py_retval = libvirt_intWrap(autostart);
    return(py_retval);
}

static PyObject *
libvirt_virStoragePoolGetInfo(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval;
    virStoragePoolPtr pool;
    PyObject *pyobj_pool;
    virStoragePoolInfo info;

    if (!PyArg_ParseTuple(args, (char *)"O:virStoragePoolGetInfo", &pyobj_pool))
        return(NULL);
    pool = (virStoragePoolPtr) PyvirStoragePool_Get(pyobj_pool);

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virStoragePoolGetInfo(pool, &info);
    LIBVIRT_END_ALLOW_THREADS;
    if (c_retval < 0)
        return VIR_PY_NONE;

    if ((py_retval = PyList_New(4)) == NULL)
        return VIR_PY_NONE;

    PyList_SetItem(py_retval, 0, libvirt_intWrap((int) info.state));
    PyList_SetItem(py_retval, 1,
                   libvirt_longlongWrap((unsigned long long) info.capacity));
    PyList_SetItem(py_retval, 2,
                   libvirt_longlongWrap((unsigned long long) info.allocation));
    PyList_SetItem(py_retval, 3,
                   libvirt_longlongWrap((unsigned long long) info.available));
    return(py_retval);
}


static PyObject *
libvirt_virStorageVolGetInfo(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval;
    virStorageVolPtr pool;
    PyObject *pyobj_pool;
    virStorageVolInfo info;

    if (!PyArg_ParseTuple(args, (char *)"O:virStorageVolGetInfo", &pyobj_pool))
        return(NULL);
    pool = (virStorageVolPtr) PyvirStorageVol_Get(pyobj_pool);

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virStorageVolGetInfo(pool, &info);
    LIBVIRT_END_ALLOW_THREADS;
    if (c_retval < 0)
        return VIR_PY_NONE;

    if ((py_retval = PyList_New(3)) == NULL)
        return VIR_PY_NONE;
    PyList_SetItem(py_retval, 0, libvirt_intWrap((int) info.type));
    PyList_SetItem(py_retval, 1,
                   libvirt_longlongWrap((unsigned long long) info.capacity));
    PyList_SetItem(py_retval, 2,
                   libvirt_longlongWrap((unsigned long long) info.allocation));
    return(py_retval);
}

static PyObject *
libvirt_virStoragePoolGetUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    unsigned char uuid[VIR_UUID_BUFLEN];
    virStoragePoolPtr pool;
    PyObject *pyobj_pool;
    int c_retval;

    if (!PyArg_ParseTuple(args, (char *)"O:virStoragePoolGetUUID", &pyobj_pool))
        return(NULL);
    pool = (virStoragePoolPtr) PyvirStoragePool_Get(pyobj_pool);

    if (pool == NULL)
        return VIR_PY_NONE;
    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virStoragePoolGetUUID(pool, &uuid[0]);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0)
        return VIR_PY_NONE;

    py_retval = PyString_FromStringAndSize((char *) &uuid[0], VIR_UUID_BUFLEN);

    return(py_retval);
}

static PyObject *
libvirt_virStoragePoolGetUUIDString(PyObject *self ATTRIBUTE_UNUSED,
                                    PyObject *args) {
    PyObject *py_retval;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virStoragePoolPtr pool;
    PyObject *pyobj_pool;
    int c_retval;

    if (!PyArg_ParseTuple(args, (char *)"O:virStoragePoolGetUUIDString", &pyobj_pool))
        return(NULL);
    pool = (virStoragePoolPtr) PyvirStoragePool_Get(pyobj_pool);

    if (pool == NULL)
        return VIR_PY_NONE;
    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virStoragePoolGetUUIDString(pool, &uuidstr[0]);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0)
        return VIR_PY_NONE;

    py_retval = PyString_FromString((char *) &uuidstr[0]);
    return(py_retval);
}

static PyObject *
libvirt_virStoragePoolLookupByUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    virStoragePoolPtr c_retval;
    virConnectPtr conn;
    PyObject *pyobj_conn;
    unsigned char * uuid;
    int len;

    if (!PyArg_ParseTuple(args, (char *)"Oz#:virStoragePoolLookupByUUID", &pyobj_conn, &uuid, &len))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    if ((uuid == NULL) || (len != VIR_UUID_BUFLEN))
        return VIR_PY_NONE;

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virStoragePoolLookupByUUID(conn, uuid);
    LIBVIRT_END_ALLOW_THREADS;
    py_retval = libvirt_virStoragePoolPtrWrap((virStoragePoolPtr) c_retval);
    return(py_retval);
}

static PyObject *
libvirt_virNodeListDevices(PyObject *self ATTRIBUTE_UNUSED,
                           PyObject *args) {
    PyObject *py_retval;
    char **names = NULL;
    int c_retval, i;
    virConnectPtr conn;
    PyObject *pyobj_conn;
    char *cap;
    unsigned int flags;

    if (!PyArg_ParseTuple(args, (char *)"Ozi:virNodeListDevices",
                          &pyobj_conn, &cap, &flags))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    c_retval = virNodeNumOfDevices(conn, cap, flags);
    if (c_retval < 0)
        return VIR_PY_NONE;

    if (c_retval) {
        names = malloc(sizeof(*names) * c_retval);
        if (!names)
            return VIR_PY_NONE;
        c_retval = virNodeListDevices(conn, cap, names, c_retval, flags);
        if (c_retval < 0) {
            free(names);
            return VIR_PY_NONE;
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
libvirt_virNodeDeviceListCaps(PyObject *self ATTRIBUTE_UNUSED,
                              PyObject *args) {
    PyObject *py_retval;
    char **names = NULL;
    int c_retval, i;
    virNodeDevicePtr dev;
    PyObject *pyobj_dev;

    if (!PyArg_ParseTuple(args, (char *)"O:virNodeDeviceListCaps", &pyobj_dev))
        return(NULL);
    dev = (virNodeDevicePtr) PyvirNodeDevice_Get(pyobj_dev);

    c_retval = virNodeDeviceNumOfCaps(dev);
    if (c_retval < 0)
        return VIR_PY_NONE;

    if (c_retval) {
        names = malloc(sizeof(*names) * c_retval);
        if (!names)
            return VIR_PY_NONE;
        c_retval = virNodeDeviceListCaps(dev, names, c_retval);
        if (c_retval < 0) {
            free(names);
            return VIR_PY_NONE;
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
libvirt_virSecretGetUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    unsigned char uuid[VIR_UUID_BUFLEN];
    virSecretPtr secret;
    PyObject *pyobj_secret;
    int c_retval;

    if (!PyArg_ParseTuple(args, (char *)"O:virSecretGetUUID", &pyobj_secret))
        return(NULL);
    secret = (virSecretPtr) PyvirSecret_Get(pyobj_secret);

    if (secret == NULL)
        return VIR_PY_NONE;
    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virSecretGetUUID(secret, &uuid[0]);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0)
        return VIR_PY_NONE;
    py_retval = PyString_FromStringAndSize((char *) &uuid[0], VIR_UUID_BUFLEN);

    return(py_retval);
}

static PyObject *
libvirt_virSecretGetUUIDString(PyObject *self ATTRIBUTE_UNUSED,
                               PyObject *args) {
    PyObject *py_retval;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virSecretPtr dom;
    PyObject *pyobj_dom;
    int c_retval;

    if (!PyArg_ParseTuple(args, (char *)"O:virSecretGetUUIDString",
                          &pyobj_dom))
        return(NULL);
    dom = (virSecretPtr) PyvirSecret_Get(pyobj_dom);

    if (dom == NULL)
        return VIR_PY_NONE;
    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virSecretGetUUIDString(dom, &uuidstr[0]);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0)
        return VIR_PY_NONE;

    py_retval = PyString_FromString((char *) &uuidstr[0]);
    return(py_retval);
}

static PyObject *
libvirt_virSecretLookupByUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    virSecretPtr c_retval;
    virConnectPtr conn;
    PyObject *pyobj_conn;
    unsigned char * uuid;
    int len;

    if (!PyArg_ParseTuple(args, (char *)"Oz#:virSecretLookupByUUID", &pyobj_conn, &uuid, &len))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    if ((uuid == NULL) || (len != VIR_UUID_BUFLEN))
        return VIR_PY_NONE;

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virSecretLookupByUUID(conn, uuid);
    LIBVIRT_END_ALLOW_THREADS;
    py_retval = libvirt_virSecretPtrWrap((virSecretPtr) c_retval);
    return(py_retval);
}


static PyObject *
libvirt_virConnectListSecrets(PyObject *self ATTRIBUTE_UNUSED,
                              PyObject *args) {
    PyObject *py_retval;
    char **uuids = NULL;
    virConnectPtr conn;
    int c_retval, i;
    PyObject *pyobj_conn;

    if (!PyArg_ParseTuple(args, (char *)"O:virConnectListSecrets", &pyobj_conn))
        return NULL;
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virConnectNumOfSecrets(conn);
    LIBVIRT_END_ALLOW_THREADS;
    if (c_retval < 0)
        return VIR_PY_NONE;

    if (c_retval) {
        uuids = malloc(sizeof(*uuids) * c_retval);
        if (!uuids)
            return VIR_PY_NONE;
        LIBVIRT_BEGIN_ALLOW_THREADS;
        c_retval = virConnectListSecrets(conn, uuids, c_retval);
        LIBVIRT_END_ALLOW_THREADS;
        if (c_retval < 0) {
            free(uuids);
            return VIR_PY_NONE;
        }
    }
    py_retval = PyList_New(c_retval);

    if (uuids) {
        for (i = 0;i < c_retval;i++) {
            PyList_SetItem(py_retval, i, libvirt_constcharPtrWrap(uuids[i]));
            free(uuids[i]);
        }
        free(uuids);
    }

    return py_retval;
}

static PyObject *
libvirt_virSecretGetValue(PyObject *self ATTRIBUTE_UNUSED,
                          PyObject *args) {
    PyObject *py_retval;
    unsigned char *c_retval;
    size_t size;
    virSecretPtr secret;
    PyObject *pyobj_secret;
    unsigned int flags;

    if (!PyArg_ParseTuple(args, (char *)"Oi:virSecretGetValue", &pyobj_secret,
                          &flags))
        return NULL;
    secret = (virSecretPtr) PyvirSecret_Get(pyobj_secret);

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virSecretGetValue(secret, &size, flags);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval == NULL)
        return VIR_PY_NONE;

    py_retval = PyString_FromStringAndSize((const char *)c_retval, size);
    memset(c_retval, 0, size);
    free(c_retval);

    return py_retval;
}

static PyObject *
libvirt_virSecretSetValue(PyObject *self ATTRIBUTE_UNUSED,
                          PyObject *args) {
    PyObject *py_retval;
    int c_retval;
    virSecretPtr secret;
    PyObject *pyobj_secret;
    const char *value;
    int size;
    unsigned int flags;

    if (!PyArg_ParseTuple(args, (char *)"Oz#i:virSecretSetValue", &pyobj_secret,
                          &value, &size, &flags))
        return NULL;
    secret = (virSecretPtr) PyvirSecret_Get(pyobj_secret);

    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virSecretSetValue(secret, (const unsigned char *)value, size,
                                 flags);
    LIBVIRT_END_ALLOW_THREADS;

    py_retval = libvirt_intWrap(c_retval);
    return py_retval;
}

/*******************************************
 * Helper functions to avoid importing modules
 * for every callback
 *******************************************/
static PyObject *libvirt_module    = NULL;
static PyObject *libvirt_dict      = NULL;
static PyObject *libvirt_dom_class = NULL;

static PyObject *
getLibvirtModuleObject (void) {
    if(libvirt_module)
        return libvirt_module;

    // PyImport_ImportModule returns a new reference
    /* Bogus (char *) cast for RHEL-5 python API brokenness */
    libvirt_module = PyImport_ImportModule((char *)"libvirt");
    if(!libvirt_module) {
#if DEBUG_ERROR
        printf("%s Error importing libvirt module\n", __FUNCTION__);
#endif
        PyErr_Print();
        return NULL;
    }

    return libvirt_module;
}

static PyObject *
getLibvirtDictObject (void) {
    if(libvirt_dict)
        return libvirt_dict;

    // PyModule_GetDict returns a borrowed reference
    libvirt_dict = PyModule_GetDict(getLibvirtModuleObject());
    if(!libvirt_dict) {
#if DEBUG_ERROR
        printf("%s Error importing libvirt dictionary\n", __FUNCTION__);
#endif
        PyErr_Print();
        return NULL;
    }

    Py_INCREF(libvirt_dict);
    return libvirt_dict;
}

static PyObject *
getLibvirtDomainClassObject (void) {
    if(libvirt_dom_class)
        return libvirt_dom_class;

    // PyDict_GetItemString returns a borrowed reference
    libvirt_dom_class = PyDict_GetItemString(getLibvirtDictObject(),
                                             "virDomain");
    if(!libvirt_dom_class) {
#if DEBUG_ERROR
        printf("%s Error importing virDomain class\n", __FUNCTION__);
#endif
        PyErr_Print();
        return NULL;
    }

    Py_INCREF(libvirt_dom_class);
    return libvirt_dom_class;
}
/*******************************************
 * Domain Events
 *******************************************/

static int
libvirt_virConnectDomainEventCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                      virDomainPtr dom,
                                      int event,
                                      int detail,
                                      void *opaque)
{
    PyObject *pyobj_ret;

    PyObject *pyobj_conn_inst = (PyObject*)opaque;
    PyObject *pyobj_dom;

    PyObject *pyobj_dom_args;
    PyObject *pyobj_dom_inst;

    PyObject *dom_class;
    int ret = -1;

    LIBVIRT_ENSURE_THREAD_STATE;

    /* Create a python instance of this virDomainPtr */
    virDomainRef(dom);
    pyobj_dom = libvirt_virDomainPtrWrap(dom);
    pyobj_dom_args = PyTuple_New(2);
    if(PyTuple_SetItem(pyobj_dom_args, 0, pyobj_conn_inst)!=0) {
#if DEBUG_ERROR
        printf("%s error creating tuple",__FUNCTION__);
#endif
        goto cleanup;
    }
    if(PyTuple_SetItem(pyobj_dom_args, 1, pyobj_dom)!=0) {
#if DEBUG_ERROR
        printf("%s error creating tuple",__FUNCTION__);
#endif
        goto cleanup;
    }
    Py_INCREF(pyobj_conn_inst);

    dom_class = getLibvirtDomainClassObject();
    if(!PyClass_Check(dom_class)) {
#if DEBUG_ERROR
        printf("%s dom_class is not a class!\n", __FUNCTION__);
#endif
        goto cleanup;
    }

    pyobj_dom_inst = PyInstance_New(dom_class,
                                    pyobj_dom_args,
                                    NULL);

    Py_DECREF(pyobj_dom_args);

    if(!pyobj_dom_inst) {
#if DEBUG_ERROR
        printf("%s Error creating a python instance of virDomain\n", __FUNCTION__);
#endif
        PyErr_Print();
        goto cleanup;
    }

    /* Call the Callback Dispatcher */
    pyobj_ret = PyObject_CallMethod(pyobj_conn_inst,
                                    (char*)"dispatchDomainEventCallbacks",
                                    (char*)"Oii",
                                    pyobj_dom_inst,
                                    event,
                                    detail);

    Py_DECREF(pyobj_dom_inst);

    if(!pyobj_ret) {
#if DEBUG_ERROR
        printf("%s - ret:%p\n", __FUNCTION__, pyobj_ret);
#endif
        PyErr_Print();
    } else {
        Py_DECREF(pyobj_ret);
        ret = 0;
    }


cleanup:
    LIBVIRT_RELEASE_THREAD_STATE;
    return ret;
}

static PyObject *
libvirt_virConnectDomainEventRegister(ATTRIBUTE_UNUSED PyObject * self,
                                      PyObject * args)
{
    PyObject *py_retval;        /* return value */
    PyObject *pyobj_conn;       /* virConnectPtr */
    PyObject *pyobj_conn_inst;  /* virConnect Python object */

    virConnectPtr conn;
    int ret = 0;

    if (!PyArg_ParseTuple
        (args, (char *) "OO:virConnectDomainEventRegister",
                        &pyobj_conn, &pyobj_conn_inst)) {
#if DEBUG_ERROR
        printf("%s failed parsing tuple\n", __FUNCTION__);
#endif
        return VIR_PY_INT_FAIL;
    }

#ifdef DEBUG_ERROR
    printf("libvirt_virConnectDomainEventRegister(%p %p) called\n",
           pyobj_conn, pyobj_conn_inst);
#endif
    conn   = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    Py_INCREF(pyobj_conn_inst);

    LIBVIRT_BEGIN_ALLOW_THREADS;

    ret = virConnectDomainEventRegister(conn,
                                        libvirt_virConnectDomainEventCallback,
                                        (void *)pyobj_conn_inst, NULL);

    LIBVIRT_END_ALLOW_THREADS;

    py_retval = libvirt_intWrap(ret);
    return (py_retval);
}

static PyObject *
libvirt_virConnectDomainEventDeregister(ATTRIBUTE_UNUSED PyObject * self,
                                        PyObject * args)
{
    PyObject *py_retval;
    PyObject *pyobj_conn;
    PyObject *pyobj_conn_inst;

    virConnectPtr conn;
    int ret = 0;

    if (!PyArg_ParseTuple
        (args, (char *) "OO:virConnectDomainEventDeregister",
         &pyobj_conn, &pyobj_conn_inst))
        return (NULL);

#ifdef DEBUG_ERROR
    printf("libvirt_virConnectDomainEventDeregister(%p) called\n", pyobj_conn);
#endif

    conn   = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    LIBVIRT_BEGIN_ALLOW_THREADS;

    ret = virConnectDomainEventDeregister(conn, libvirt_virConnectDomainEventCallback);

    LIBVIRT_END_ALLOW_THREADS;

    Py_DECREF(pyobj_conn_inst);
    py_retval = libvirt_intWrap(ret);
    return (py_retval);
}

/*******************************************
 * Event Impl
 *******************************************/
static PyObject *addHandleObj     = NULL;
static char *addHandleName        = NULL;
static PyObject *updateHandleObj  = NULL;
static char *updateHandleName     = NULL;
static PyObject *removeHandleObj  = NULL;
static char *removeHandleName     = NULL;
static PyObject *addTimeoutObj    = NULL;
static char *addTimeoutName       = NULL;
static PyObject *updateTimeoutObj = NULL;
static char *updateTimeoutName    = NULL;
static PyObject *removeTimeoutObj = NULL;
static char *removeTimeoutName    = NULL;

#define NAME(fn) ( fn ## Name ? fn ## Name : # fn )

static int
libvirt_virEventAddHandleFunc  (int fd,
                                int event,
                                virEventHandleCallback cb,
                                void *opaque,
                                virFreeCallback ff)
{
    PyObject *result;
    PyObject *python_cb;
    PyObject *cb_obj;
    PyObject *ff_obj;
    PyObject *opaque_obj;
    PyObject *cb_args;
    PyObject *pyobj_args;
    int retval = -1;

    LIBVIRT_ENSURE_THREAD_STATE;

    /* Lookup the python callback */
    python_cb = PyDict_GetItemString(getLibvirtDictObject(),
                                     "eventInvokeHandleCallback");
    if(!python_cb) {
#if DEBUG_ERROR
        printf("%s: Error finding eventInvokeHandleCallback\n", __FUNCTION__);
#endif
        PyErr_Print();
        PyErr_Clear();
        goto cleanup;
    }
    if (!PyCallable_Check(python_cb)) {
#if DEBUG_ERROR
        char *name = py_str(python_cb);
        printf("%s: %s is not callable\n", __FUNCTION__,
               name ? name : "libvirt.eventInvokeHandleCallback");
        free(name);
#endif
        goto cleanup;
    }
    Py_INCREF(python_cb);

    /* create tuple for cb */
    cb_obj = libvirt_virEventHandleCallbackWrap(cb);
    ff_obj = libvirt_virFreeCallbackWrap(ff);
    opaque_obj = libvirt_virVoidPtrWrap(opaque);

    cb_args = PyTuple_New(3);
    PyTuple_SetItem(cb_args, 0, cb_obj);
    PyTuple_SetItem(cb_args, 1, opaque_obj);
    PyTuple_SetItem(cb_args, 2, ff_obj);

    pyobj_args = PyTuple_New(4);
    PyTuple_SetItem(pyobj_args, 0, libvirt_intWrap(fd));
    PyTuple_SetItem(pyobj_args, 1, libvirt_intWrap(event));
    PyTuple_SetItem(pyobj_args, 2, python_cb);
    PyTuple_SetItem(pyobj_args, 3, cb_args);

    result = PyEval_CallObject(addHandleObj, pyobj_args);
    if (!result) {
        PyErr_Print();
        PyErr_Clear();
    } else if (!PyInt_Check(result)) {
#if DEBUG_ERROR
        printf("%s: %s should return an int\n", __FUNCTION__, NAME(addHandle));
#endif
    } else {
        retval = (int)PyInt_AsLong(result);
    }

    Py_XDECREF(result);
    Py_DECREF(pyobj_args);

cleanup:
    LIBVIRT_RELEASE_THREAD_STATE;

    return retval;
}

static void
libvirt_virEventUpdateHandleFunc(int watch, int event)
{
    PyObject *result;
    PyObject *pyobj_args;

    LIBVIRT_ENSURE_THREAD_STATE;

    pyobj_args = PyTuple_New(2);
    PyTuple_SetItem(pyobj_args, 0, libvirt_intWrap(watch));
    PyTuple_SetItem(pyobj_args, 1, libvirt_intWrap(event));

    result = PyEval_CallObject(updateHandleObj, pyobj_args);
    if (!result) {
        PyErr_Print();
        PyErr_Clear();
    }

    Py_XDECREF(result);
    Py_DECREF(pyobj_args);

    LIBVIRT_RELEASE_THREAD_STATE;
}


static int
libvirt_virEventRemoveHandleFunc(int watch)
{
    PyObject *result;
    PyObject *pyobj_args;
    PyObject *opaque;
    PyObject *ff;
    int retval = -1;
    virFreeCallback cff;

    LIBVIRT_ENSURE_THREAD_STATE;

    pyobj_args = PyTuple_New(1);
    PyTuple_SetItem(pyobj_args, 0, libvirt_intWrap(watch));

    result = PyEval_CallObject(removeHandleObj, pyobj_args);
    if (!result) {
        PyErr_Print();
        PyErr_Clear();
    } else if (!PyTuple_Check(result) || PyTuple_Size(result) != 3) {
#if DEBUG_ERROR
        printf("%s: %s must return opaque obj registered with %s"
               "to avoid leaking libvirt memory\n",
               __FUNCTION__, NAME(removeHandle), NAME(addHandle));
#endif
    } else {
        opaque = PyTuple_GetItem(result, 1);
        ff = PyTuple_GetItem(result, 2);
        cff = PyvirFreeCallback_Get(ff);
        if (cff)
            (*cff)(PyvirVoidPtr_Get(opaque));
        retval = 0;
    }

    Py_XDECREF(result);
    Py_DECREF(pyobj_args);

    LIBVIRT_RELEASE_THREAD_STATE;

    return retval;
}

static int
libvirt_virEventAddTimeoutFunc(int timeout,
                               virEventTimeoutCallback cb,
                               void *opaque,
                               virFreeCallback ff)
{
    PyObject *result;

    PyObject *python_cb;

    PyObject *cb_obj;
    PyObject *ff_obj;
    PyObject *opaque_obj;
    PyObject *cb_args;
    PyObject *pyobj_args;
    int retval = -1;

    LIBVIRT_ENSURE_THREAD_STATE;

    /* Lookup the python callback */
    python_cb = PyDict_GetItemString(getLibvirtDictObject(),
                                     "eventInvokeTimeoutCallback");
    if(!python_cb) {
#if DEBUG_ERROR
        printf("%s: Error finding eventInvokeTimeoutCallback\n", __FUNCTION__);
#endif
        PyErr_Print();
        PyErr_Clear();
        goto cleanup;
    }
    if (!PyCallable_Check(python_cb)) {
#if DEBUG_ERROR
        char *name = py_str(python_cb);
        printf("%s: %s is not callable\n", __FUNCTION__,
               name ? name : "libvirt.eventInvokeTimeoutCallback");
        free(name);
#endif
        goto cleanup;
    }
    Py_INCREF(python_cb);

    /* create tuple for cb */
    cb_obj = libvirt_virEventTimeoutCallbackWrap(cb);
    ff_obj = libvirt_virFreeCallbackWrap(ff);
    opaque_obj = libvirt_virVoidPtrWrap(opaque);

    cb_args = PyTuple_New(3);
    PyTuple_SetItem(cb_args, 0, cb_obj);
    PyTuple_SetItem(cb_args, 1, opaque_obj);
    PyTuple_SetItem(cb_args, 2, ff_obj);

    pyobj_args = PyTuple_New(3);

    PyTuple_SetItem(pyobj_args, 0, libvirt_intWrap(timeout));
    PyTuple_SetItem(pyobj_args, 1, python_cb);
    PyTuple_SetItem(pyobj_args, 2, cb_args);

    result = PyEval_CallObject(addTimeoutObj, pyobj_args);
    if (!result) {
        PyErr_Print();
        PyErr_Clear();
    } else if (!PyInt_Check(result)) {
#if DEBUG_ERROR
        printf("%s: %s should return an int\n", __FUNCTION__, NAME(addTimeout));
#endif
    } else {
        retval = (int)PyInt_AsLong(result);
    }

    Py_XDECREF(result);
    Py_DECREF(pyobj_args);

cleanup:
    LIBVIRT_RELEASE_THREAD_STATE;
    return retval;
}

static void
libvirt_virEventUpdateTimeoutFunc(int timer, int timeout)
{
    PyObject *result = NULL;
    PyObject *pyobj_args;

    LIBVIRT_ENSURE_THREAD_STATE;

    pyobj_args = PyTuple_New(2);
    PyTuple_SetItem(pyobj_args, 0, libvirt_intWrap(timer));
    PyTuple_SetItem(pyobj_args, 1, libvirt_intWrap(timeout));

    result = PyEval_CallObject(updateTimeoutObj, pyobj_args);
    if (!result) {
        PyErr_Print();
        PyErr_Clear();
    }

    Py_XDECREF(result);
    Py_DECREF(pyobj_args);

    LIBVIRT_RELEASE_THREAD_STATE;
}

static int
libvirt_virEventRemoveTimeoutFunc(int timer)
{
    PyObject *result = NULL;
    PyObject *pyobj_args;
    PyObject *opaque;
    PyObject *ff;
    int retval = -1;
    virFreeCallback cff;

    LIBVIRT_ENSURE_THREAD_STATE;

    pyobj_args = PyTuple_New(1);
    PyTuple_SetItem(pyobj_args, 0, libvirt_intWrap(timer));

    result = PyEval_CallObject(removeTimeoutObj, pyobj_args);
    if (!result) {
        PyErr_Print();
        PyErr_Clear();
    } else if (!PyTuple_Check(result) || PyTuple_Size(result) != 3) {
#if DEBUG_ERROR
        printf("%s: %s must return opaque obj registered with %s"
               "to avoid leaking libvirt memory\n",
               __FUNCTION__, NAME(removeTimeout), NAME(addTimeout));
#endif
    } else {
        opaque = PyTuple_GetItem(result, 1);
        ff = PyTuple_GetItem(result, 2);
        cff = PyvirFreeCallback_Get(ff);
        if (cff)
            (*cff)(PyvirVoidPtr_Get(opaque));
        retval = 0;
    }

    Py_XDECREF(result);
    Py_DECREF(pyobj_args);

    LIBVIRT_RELEASE_THREAD_STATE;

    return retval;
}

static PyObject *
libvirt_virEventRegisterImpl(ATTRIBUTE_UNUSED PyObject * self,
                             PyObject * args)
{
    /* Unref the previously-registered impl (if any) */
    Py_XDECREF(addHandleObj);
    free(addHandleName);
    Py_XDECREF(updateHandleObj);
    free(updateHandleName);
    Py_XDECREF(removeHandleObj);
    free(removeHandleName);
    Py_XDECREF(addTimeoutObj);
    free(addTimeoutName);
    Py_XDECREF(updateTimeoutObj);
    free(updateTimeoutName);
    Py_XDECREF(removeTimeoutObj);
    free(removeTimeoutName);

    /* Parse and check arguments */
    if (!PyArg_ParseTuple(args, (char *) "OOOOOO:virEventRegisterImpl",
                          &addHandleObj, &updateHandleObj,
                          &removeHandleObj, &addTimeoutObj,
                          &updateTimeoutObj, &removeTimeoutObj) ||
        !PyCallable_Check(addHandleObj) ||
        !PyCallable_Check(updateHandleObj) ||
        !PyCallable_Check(removeHandleObj) ||
        !PyCallable_Check(addTimeoutObj) ||
        !PyCallable_Check(updateTimeoutObj) ||
        !PyCallable_Check(removeTimeoutObj))
        return VIR_PY_INT_FAIL;

    /* Get argument string representations (for error reporting) */
    addHandleName = py_str(addTimeoutObj);
    updateHandleName = py_str(updateHandleObj);
    removeHandleName = py_str(removeHandleObj);
    addTimeoutName = py_str(addTimeoutObj);
    updateTimeoutName = py_str(updateTimeoutObj);
    removeTimeoutName = py_str(removeTimeoutObj);

    /* Inc refs since we're holding onto these objects until
     * the next call (if any) to this function.
     */
    Py_INCREF(addHandleObj);
    Py_INCREF(updateHandleObj);
    Py_INCREF(removeHandleObj);
    Py_INCREF(addTimeoutObj);
    Py_INCREF(updateTimeoutObj);
    Py_INCREF(removeTimeoutObj);

    LIBVIRT_BEGIN_ALLOW_THREADS;

    /* Now register our C EventImpl, which will dispatch
     * to the Python callbacks passed in as args.
     */
    virEventRegisterImpl(libvirt_virEventAddHandleFunc,
                         libvirt_virEventUpdateHandleFunc,
                         libvirt_virEventRemoveHandleFunc,
                         libvirt_virEventAddTimeoutFunc,
                         libvirt_virEventUpdateTimeoutFunc,
                         libvirt_virEventRemoveTimeoutFunc);

    LIBVIRT_END_ALLOW_THREADS;

    return VIR_PY_INT_SUCCESS;
}

static PyObject *
libvirt_virEventInvokeHandleCallback(PyObject *self ATTRIBUTE_UNUSED,
                                     PyObject *args)
{
    int watch, fd, event;
    PyObject *py_f;
    PyObject *py_opaque;
    virEventHandleCallback cb;
    void *opaque;

    if (!PyArg_ParseTuple
        (args, (char *) "iiiOO:virEventInvokeHandleCallback",
         &watch, &fd, &event, &py_f, &py_opaque
        ))
        return VIR_PY_INT_FAIL;

    cb     = (virEventHandleCallback) PyvirEventHandleCallback_Get(py_f);
    opaque = (void *) PyvirVoidPtr_Get(py_opaque);

    if(cb)
        cb (watch, fd, event, opaque);

    return VIR_PY_INT_SUCCESS;
}

static PyObject *
libvirt_virEventInvokeTimeoutCallback(PyObject *self ATTRIBUTE_UNUSED,
                                      PyObject *args)
{
    int timer;
    PyObject *py_f;
    PyObject *py_opaque;
    virEventTimeoutCallback cb;
    void *opaque;

    if (!PyArg_ParseTuple
        (args, (char *) "iOO:virEventInvokeTimeoutCallback",
                        &timer, &py_f, &py_opaque
        ))
        return VIR_PY_INT_FAIL;

    cb     = (virEventTimeoutCallback) PyvirEventTimeoutCallback_Get(py_f);
    opaque = (void *) PyvirVoidPtr_Get(py_opaque);
    if(cb)
        cb (timer, opaque);

    return VIR_PY_INT_SUCCESS;
}

/************************************************************************
 *									*
 *			The registration stuff				*
 *									*
 ************************************************************************/
static PyMethodDef libvirtMethods[] = {
#include "libvirt-export.c"
    {(char *) "virGetVersion", libvirt_virGetVersion, METH_VARARGS, NULL},
    {(char *) "virConnectOpenAuth", libvirt_virConnectOpenAuth, METH_VARARGS, NULL},
    {(char *) "virConnectListDomainsID", libvirt_virConnectListDomainsID, METH_VARARGS, NULL},
    {(char *) "virConnectListDefinedDomains", libvirt_virConnectListDefinedDomains, METH_VARARGS, NULL},
    {(char *) "virConnectDomainEventRegister", libvirt_virConnectDomainEventRegister, METH_VARARGS, NULL},
    {(char *) "virConnectDomainEventDeregister", libvirt_virConnectDomainEventDeregister, METH_VARARGS, NULL},
    {(char *) "virDomainGetInfo", libvirt_virDomainGetInfo, METH_VARARGS, NULL},
    {(char *) "virNodeGetInfo", libvirt_virNodeGetInfo, METH_VARARGS, NULL},
    {(char *) "virDomainGetUUID", libvirt_virDomainGetUUID, METH_VARARGS, NULL},
    {(char *) "virDomainGetUUIDString", libvirt_virDomainGetUUIDString, METH_VARARGS, NULL},
    {(char *) "virDomainLookupByUUID", libvirt_virDomainLookupByUUID, METH_VARARGS, NULL},
    {(char *) "virRegisterErrorHandler", libvirt_virRegisterErrorHandler, METH_VARARGS, NULL},
    {(char *) "virGetLastError", libvirt_virGetLastError, METH_VARARGS, NULL},
    {(char *) "virConnGetLastError", libvirt_virConnGetLastError, METH_VARARGS, NULL},
    {(char *) "virConnectListNetworks", libvirt_virConnectListNetworks, METH_VARARGS, NULL},
    {(char *) "virConnectListDefinedNetworks", libvirt_virConnectListDefinedNetworks, METH_VARARGS, NULL},
    {(char *) "virNetworkGetUUID", libvirt_virNetworkGetUUID, METH_VARARGS, NULL},
    {(char *) "virNetworkGetUUIDString", libvirt_virNetworkGetUUIDString, METH_VARARGS, NULL},
    {(char *) "virNetworkLookupByUUID", libvirt_virNetworkLookupByUUID, METH_VARARGS, NULL},
    {(char *) "virDomainGetAutostart", libvirt_virDomainGetAutostart, METH_VARARGS, NULL},
    {(char *) "virNetworkGetAutostart", libvirt_virNetworkGetAutostart, METH_VARARGS, NULL},
    {(char *) "virDomainBlockStats", libvirt_virDomainBlockStats, METH_VARARGS, NULL},
    {(char *) "virDomainInterfaceStats", libvirt_virDomainInterfaceStats, METH_VARARGS, NULL},
    {(char *) "virNodeGetCellsFreeMemory", libvirt_virNodeGetCellsFreeMemory, METH_VARARGS, NULL},
    {(char *) "virDomainGetSchedulerType", libvirt_virDomainGetSchedulerType, METH_VARARGS, NULL},
    {(char *) "virDomainGetSchedulerParameters", libvirt_virDomainGetSchedulerParameters, METH_VARARGS, NULL},
    {(char *) "virDomainSetSchedulerParameters", libvirt_virDomainSetSchedulerParameters, METH_VARARGS, NULL},
    {(char *) "virDomainGetVcpus", libvirt_virDomainGetVcpus, METH_VARARGS, NULL},
    {(char *) "virDomainPinVcpu", libvirt_virDomainPinVcpu, METH_VARARGS, NULL},
    {(char *) "virConnectListStoragePools", libvirt_virConnectListStoragePools, METH_VARARGS, NULL},
    {(char *) "virConnectListDefinedStoragePools", libvirt_virConnectListDefinedStoragePools, METH_VARARGS, NULL},
    {(char *) "virStoragePoolGetAutostart", libvirt_virStoragePoolGetAutostart, METH_VARARGS, NULL},
    {(char *) "virStoragePoolListVolumes", libvirt_virStoragePoolListVolumes, METH_VARARGS, NULL},
    {(char *) "virStoragePoolGetInfo", libvirt_virStoragePoolGetInfo, METH_VARARGS, NULL},
    {(char *) "virStorageVolGetInfo", libvirt_virStorageVolGetInfo, METH_VARARGS, NULL},
    {(char *) "virStoragePoolGetUUID", libvirt_virStoragePoolGetUUID, METH_VARARGS, NULL},
    {(char *) "virStoragePoolGetUUIDString", libvirt_virStoragePoolGetUUIDString, METH_VARARGS, NULL},
    {(char *) "virStoragePoolLookupByUUID", libvirt_virStoragePoolLookupByUUID, METH_VARARGS, NULL},
    {(char *) "virEventRegisterImpl", libvirt_virEventRegisterImpl, METH_VARARGS, NULL},
    {(char *) "virEventInvokeHandleCallback", libvirt_virEventInvokeHandleCallback, METH_VARARGS, NULL},
    {(char *) "virEventInvokeTimeoutCallback", libvirt_virEventInvokeTimeoutCallback, METH_VARARGS, NULL},
    {(char *) "virNodeListDevices", libvirt_virNodeListDevices, METH_VARARGS, NULL},
    {(char *) "virNodeDeviceListCaps", libvirt_virNodeDeviceListCaps, METH_VARARGS, NULL},
    {(char *) "virSecretGetUUID", libvirt_virSecretGetUUID, METH_VARARGS, NULL},
    {(char *) "virSecretGetUUIDString", libvirt_virSecretGetUUIDString, METH_VARARGS, NULL},
    {(char *) "virSecretLookupByUUID", libvirt_virSecretLookupByUUID, METH_VARARGS, NULL},
    {(char *) "virConnectListSecrets", libvirt_virConnectListSecrets, METH_VARARGS, NULL},
    {(char *) "virSecretGetValue", libvirt_virSecretGetValue, METH_VARARGS, NULL},
    {(char *) "virSecretSetValue", libvirt_virSecretSetValue, METH_VARARGS, NULL},
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

    /* initialize the python extension module */
    Py_InitModule((char *)
#ifndef __CYGWIN__
                  "libvirtmod"
#else
                  "cygvirtmod"
#endif
                  , libvirtMethods);

    initialized = 1;
}
