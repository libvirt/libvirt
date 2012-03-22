/*
 * libvir.c: this modules implements the main part of the glue of the
 *           libvir library and the Python interpreter. It provides the
 *           entry points where an automatically generated stub is
 *           unpractical
 *
 * Copyright (C) 2011-2012 Red Hat, Inc.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

/* Horrible kludge to work around even more horrible name-space pollution
   via Python.h.  That file includes /usr/include/python2.5/pyconfig*.h,
   which has over 180 autoconf-style HAVE_* definitions.  Shame on them.  */
#undef HAVE_PTHREAD_H

#include <Python.h>
#include "libvirt/libvirt-qemu.h"
#include "libvirt/virterror.h"
#include "typewrappers.h"
#include "libvirt-qemu.h"

#ifndef __CYGWIN__
extern void initlibvirtmod_qemu(void);
#else
extern void initcygvirtmod_qemu(void);
#endif

#if 0
# define DEBUG_ERROR 1
#endif

#if DEBUG_ERROR
# define DEBUG(fmt, ...)            \
   printf(fmt, __VA_ARGS__)
#else
# define DEBUG(fmt, ...)            \
   do {} while (0)
#endif

/* The two-statement sequence "Py_INCREF(Py_None); return Py_None;"
   is so common that we encapsulate it here.  Now, each use is simply
   return VIR_PY_NONE;  */
#define VIR_PY_NONE (Py_INCREF (Py_None), Py_None)
#define VIR_PY_INT_FAIL (libvirt_intWrap(-1))
#define VIR_PY_INT_SUCCESS (libvirt_intWrap(0))

/************************************************************************
 *									*
 *		Statistics						*
 *									*
 ************************************************************************/

static PyObject *
libvirt_qemu_virDomainQemuMonitorCommand(PyObject *self ATTRIBUTE_UNUSED,
                                    PyObject *args) {
    PyObject *py_retval;
    char *result = NULL;
    virDomainPtr domain;
    PyObject *pyobj_domain;
    unsigned int flags;
    char *cmd;
    int c_retval;

    if (!PyArg_ParseTuple(args, (char *)"Ozi:virDomainQemuMonitorCommand",
                          &pyobj_domain, &cmd, &flags))
        return NULL;
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    if (domain == NULL)
        return VIR_PY_NONE;
    LIBVIRT_BEGIN_ALLOW_THREADS;
    c_retval = virDomainQemuMonitorCommand(domain, cmd, &result, flags);
    LIBVIRT_END_ALLOW_THREADS;

    if (c_retval < 0)
        return VIR_PY_NONE;

    py_retval = PyString_FromString(result);
    return py_retval;
}

/************************************************************************
 *									*
 *			The registration stuff				*
 *									*
 ************************************************************************/
static PyMethodDef libvirtQemuMethods[] = {
#include "libvirt-qemu-export.c"
    {(char *) "virDomainQemuMonitorCommand", libvirt_qemu_virDomainQemuMonitorCommand, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

void
#ifndef __CYGWIN__
initlibvirtmod_qemu
#else
initcygvirtmod_qemu
#endif
  (void)
{
    static int initialized = 0;

    if (initialized != 0)
        return;

    if (virInitialize() < 0)
        return;

    /* initialize the python extension module */
    Py_InitModule((char *)
#ifndef __CYGWIN__
                  "libvirtmod_qemu"
#else
                  "cygvirtmod_qemu"
#endif
                  , libvirtQemuMethods);

    initialized = 1;
}
