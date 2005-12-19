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

/************************************************************************
 *									*
 *			The registration stuff				*
 *									*
 ************************************************************************/
static PyMethodDef libvirMethods[] = {
#include "libvir-export.c"
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
