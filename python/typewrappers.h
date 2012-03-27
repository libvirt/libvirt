/*
 * libvirt_wrap.h: type wrappers for libvir python bindings
 *
 * Copyright (C) 2005, 2011-2012 Red Hat, Inc.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <Python.h>
#include <stdbool.h>
#include "libvirt/libvirt.h"
#include "libvirt/virterror.h"

#ifdef __GNUC__
# ifdef ATTRIBUTE_UNUSED
#  undef ATTRIBUTE_UNUSED
# endif
# ifndef ATTRIBUTE_UNUSED
#  define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# endif /* ATTRIBUTE_UNUSED */
#else
# define ATTRIBUTE_UNUSED
#endif

/* Work around really old python.  */
#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION < 5
typedef ssize_t Py_ssize_t;
#endif

#define PyvirConnect_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirConnect_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virConnectPtr obj;
} PyvirConnect_Object;


#define PyvirDomain_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirDomain_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virDomainPtr obj;
} PyvirDomain_Object;


#define PyvirNetwork_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirNetwork_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virNetworkPtr obj;
} PyvirNetwork_Object;


#define PyvirInterface_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirInterface_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virInterfacePtr obj;
} PyvirInterface_Object;


#define PyvirStoragePool_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirStoragePool_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virStoragePoolPtr obj;
} PyvirStoragePool_Object;


#define PyvirStorageVol_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirStorageVol_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virStorageVolPtr obj;
} PyvirStorageVol_Object;


#define PyvirNodeDevice_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirNodeDevice_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virNodeDevicePtr obj;
} PyvirNodeDevice_Object;

#define PyvirSecret_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirSecret_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virSecretPtr obj;
} PyvirSecret_Object;

#define PyvirNWFilter_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirNWFilter_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virNWFilterPtr obj;
} PyvirNWFilter_Object;


#define PyvirStream_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirStream_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virStreamPtr obj;
} PyvirStream_Object;


#define PyvirDomainSnapshot_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirDomainSnapshot_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virDomainSnapshotPtr obj;
} PyvirDomainSnapshot_Object;


#define PyvirEventHandleCallback_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirEventHandleCallback_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virEventHandleCallback obj;
} PyvirEventHandleCallback_Object;

#define PyvirEventTimeoutCallback_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirEventTimeoutCallback_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virEventTimeoutCallback obj;
} PyvirEventTimeoutCallback_Object;

#define PyvirFreeCallback_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirFreeCallback_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virFreeCallback obj;
} PyvirFreeCallback_Object;

#define PyvirVoidPtr_Get(v) (((v) == Py_None) ? NULL : \
        (((PyvirVoidPtr_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    void* obj;
} PyvirVoidPtr_Object;

PyObject * libvirt_intWrap(int val);
PyObject * libvirt_longWrap(long val);
PyObject * libvirt_ulongWrap(unsigned long val);
PyObject * libvirt_longlongWrap(long long val);
PyObject * libvirt_ulonglongWrap(unsigned long long val);
PyObject * libvirt_charPtrWrap(char *str);
PyObject * libvirt_charPtrSizeWrap(char *str, Py_ssize_t size);
PyObject * libvirt_constcharPtrWrap(const char *str);
int libvirt_intUnwrap(PyObject *obj, int *val);
int libvirt_uintUnwrap(PyObject *obj, unsigned int *val);
int libvirt_longUnwrap(PyObject *obj, long *val);
int libvirt_ulongUnwrap(PyObject *obj, unsigned long *val);
int libvirt_longlongUnwrap(PyObject *obj, long long *val);
int libvirt_ulonglongUnwrap(PyObject *obj, unsigned long long *val);
int libvirt_doubleUnwrap(PyObject *obj, double *val);
int libvirt_boolUnwrap(PyObject *obj, bool *val);
PyObject * libvirt_virConnectPtrWrap(virConnectPtr node);
PyObject * libvirt_virDomainPtrWrap(virDomainPtr node);
PyObject * libvirt_virNetworkPtrWrap(virNetworkPtr node);
PyObject * libvirt_virInterfacePtrWrap(virInterfacePtr node);
PyObject * libvirt_virStoragePoolPtrWrap(virStoragePoolPtr node);
PyObject * libvirt_virStorageVolPtrWrap(virStorageVolPtr node);
PyObject * libvirt_virEventHandleCallbackWrap(virEventHandleCallback node);
PyObject * libvirt_virEventTimeoutCallbackWrap(virEventTimeoutCallback node);
PyObject * libvirt_virFreeCallbackWrap(virFreeCallback node);
PyObject * libvirt_virVoidPtrWrap(void* node);
PyObject * libvirt_virNodeDevicePtrWrap(virNodeDevicePtr node);
PyObject * libvirt_virSecretPtrWrap(virSecretPtr node);
PyObject * libvirt_virNWFilterPtrWrap(virNWFilterPtr node);
PyObject * libvirt_virStreamPtrWrap(virStreamPtr node);
PyObject * libvirt_virDomainSnapshotPtrWrap(virDomainSnapshotPtr node);


/* Provide simple macro statement wrappers (adapted from GLib, in turn from Perl):
 *  LIBVIRT_STMT_START { statements; } LIBVIRT_STMT_END;
 *  can be used as a single statement, as in
 *  if (x) LIBVIRT_STMT_START { ... } LIBVIRT_STMT_END; else ...
 *
 *  When GCC is compiling C code in non-ANSI mode, it will use the
 *  compiler __extension__ to wrap the statements within `({' and '})' braces.
 *  When compiling on platforms where configure has defined
 *  HAVE_DOWHILE_MACROS, statements will be wrapped with `do' and `while (0)'.
 *  For any other platforms (SunOS4 is known to have this issue), wrap the
 *  statements with `if (1)' and `else (void) 0'.
 */
#if !(defined (LIBVIRT_STMT_START) && defined (LIBVIRT_STMT_END))
# if defined (__GNUC__) && !defined (__STRICT_ANSI__) && !defined (__cplusplus)
#  define LIBVIRT_STMT_START (void) __extension__ (
#  define LIBVIRT_STMT_END )
# else /* !(__GNUC__ && !__STRICT_ANSI__ && !__cplusplus) */
#  if defined (HAVE_DOWHILE_MACROS)
#   define LIBVIRT_STMT_START do
#   define LIBVIRT_STMT_END while (0)
#  else /* !HAVE_DOWHILE_MACROS */
#   define LIBVIRT_STMT_START if (1)
#   define LIBVIRT_STMT_END else (void) 0
#  endif /* !HAVE_DOWHILE_MACROS */
# endif /* !(__GNUC__ && !__STRICT_ANSI__ && !__cplusplus) */
#endif

#define LIBVIRT_BEGIN_ALLOW_THREADS			\
  LIBVIRT_STMT_START {					\
    PyThreadState *_save = NULL;			\
    if (PyEval_ThreadsInitialized())			\
      _save = PyEval_SaveThread();

#define LIBVIRT_END_ALLOW_THREADS                           \
  if (PyEval_ThreadsInitialized())			    \
    PyEval_RestoreThread(_save);			    \
    } LIBVIRT_STMT_END

#define LIBVIRT_ENSURE_THREAD_STATE			\
  LIBVIRT_STMT_START {					\
    PyGILState_STATE _save = PyGILState_UNLOCKED;	\
    if (PyEval_ThreadsInitialized())			\
      _save = PyGILState_Ensure();

#define LIBVIRT_RELEASE_THREAD_STATE                           \
  if (PyEval_ThreadsInitialized())			       \
    PyGILState_Release(_save);				       \
  } LIBVIRT_STMT_END
