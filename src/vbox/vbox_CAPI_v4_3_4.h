/*
 * Libvirt notice: this file is derived from the VirtualBox SDK, with
 * libvirt edits (fixing preprocessor indentation by cppi); do not
 * regenerate in the context of libvirt.
 */
/*
 *  DO NOT EDIT! This is a generated file.
 *
 *  XPCOM IDL (XPIDL) definition for VirtualBox Main API (COM interfaces)
 *  generated from XIDL (XML interface definition).
 *
 *  Source    : src/VBox/Main/idl/VirtualBox.xidl
 *  Generator : src/VBox/Main/idl/xpcidl.xsl
 *
 *  This file contains portions from the following Mozilla XPCOM files:
 *      xpcom/include/xpcom/nsID.h
 *      xpcom/include/nsIException.h
 *      xpcom/include/nsprpub/prtypes.h
 *      xpcom/include/xpcom/nsISupportsBase.h
 *
 * These files were originally triple-licensed (MPL/GPL2/LGPL2.1). Oracle
 * elects to distribute this derived work under the LGPL2.1 only.
 */

/*
 * Copyright (C) 2008-2012 Oracle Corporation
 *
 * This file is part of a free software library; you can redistribute
 * it and/or modify it under the terms of the GNU Lesser General
 * Public License version 2.1 as published by the Free Software
 * Foundation and shipped in the "COPYING.LESSER" file with this library.
 * The library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY of any kind.
 *
 * Oracle LGPL Disclaimer: For the avoidance of doubt, except that if
 * any license choice other than GPL or LGPL is available it will
 * apply instead, Oracle elects to use only the Lesser General Public
 * License version 2.1 (LGPLv2) at this time for any software where
 * a choice of LGPL license versions is made available with the
 * language indicating that LGPLv2 or any later version may be used,
 * or where a choice of which version of the LGPL is applied is
 * otherwise unspecified.
 */

#ifndef ___VirtualBox_CXPCOM_h
# define ___VirtualBox_CXPCOM_h

# ifdef __cplusplus
#  include "VirtualBox_XPCOM.h"
# else /* !__cplusplus */

#  include <stddef.h>
#  include "wchar.h"

#  if defined(WIN32)

#   define PR_EXPORT(__type) extern __declspec(dllexport) __type
#   define PR_EXPORT_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPORT(__type) __declspec(dllimport) __type
#   define PR_IMPORT_DATA(__type) __declspec(dllimport) __type

#   define PR_EXTERN(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT(__type) __declspec(dllexport) __type
#   define PR_EXTERN_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT_DATA(__type) __declspec(dllexport) __type

#   define PR_CALLBACK
#   define PR_CALLBACK_DECL
#   define PR_STATIC_CALLBACK(__x) static __x

#  elif defined(XP_BEOS)

#   define PR_EXPORT(__type) extern __declspec(dllexport) __type
#   define PR_EXPORT_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPORT(__type) extern __declspec(dllexport) __type
#   define PR_IMPORT_DATA(__type) extern __declspec(dllexport) __type

#   define PR_EXTERN(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT(__type) __declspec(dllexport) __type
#   define PR_EXTERN_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT_DATA(__type) __declspec(dllexport) __type

#   define PR_CALLBACK
#   define PR_CALLBACK_DECL
#   define PR_STATIC_CALLBACK(__x) static __x

#  elif defined(WIN16)

#   define PR_CALLBACK_DECL        __cdecl

#   if defined(_WINDLL)
#    define PR_EXPORT(__type) extern __type _cdecl _export _loadds
#    define PR_IMPORT(__type) extern __type _cdecl _export _loadds
#    define PR_EXPORT_DATA(__type) extern __type _export
#    define PR_IMPORT_DATA(__type) extern __type _export

#    define PR_EXTERN(__type) extern __type _cdecl _export _loadds
#    define PR_IMPLEMENT(__type) __type _cdecl _export _loadds
#    define PR_EXTERN_DATA(__type) extern __type _export
#    define PR_IMPLEMENT_DATA(__type) __type _export

#    define PR_CALLBACK             __cdecl __loadds
#    define PR_STATIC_CALLBACK(__x) static __x PR_CALLBACK

#   else /* this must be .EXE */
#    define PR_EXPORT(__type) extern __type _cdecl _export
#    define PR_IMPORT(__type) extern __type _cdecl _export
#    define PR_EXPORT_DATA(__type) extern __type _export
#    define PR_IMPORT_DATA(__type) extern __type _export

#    define PR_EXTERN(__type) extern __type _cdecl _export
#    define PR_IMPLEMENT(__type) __type _cdecl _export
#    define PR_EXTERN_DATA(__type) extern __type _export
#    define PR_IMPLEMENT_DATA(__type) __type _export

#    define PR_CALLBACK             __cdecl __loadds
#    define PR_STATIC_CALLBACK(__x) __x PR_CALLBACK
#   endif /* _WINDLL */

#  elif defined(XP_MAC)

#   define PR_EXPORT(__type) extern __declspec(export) __type
#   define PR_EXPORT_DATA(__type) extern __declspec(export) __type
#   define PR_IMPORT(__type) extern __declspec(export) __type
#   define PR_IMPORT_DATA(__type) extern __declspec(export) __type

#   define PR_EXTERN(__type) extern __declspec(export) __type
#   define PR_IMPLEMENT(__type) __declspec(export) __type
#   define PR_EXTERN_DATA(__type) extern __declspec(export) __type
#   define PR_IMPLEMENT_DATA(__type) __declspec(export) __type

#   define PR_CALLBACK
#   define PR_CALLBACK_DECL
#   define PR_STATIC_CALLBACK(__x) static __x

#  elif defined(XP_OS2) && defined(__declspec)

#   define PR_EXPORT(__type) extern __declspec(dllexport) __type
#   define PR_EXPORT_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPORT(__type) __declspec(dllimport) __type
#   define PR_IMPORT_DATA(__type) __declspec(dllimport) __type

#   define PR_EXTERN(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT(__type) __declspec(dllexport) __type
#   define PR_EXTERN_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT_DATA(__type) __declspec(dllexport) __type

#   define PR_CALLBACK
#   define PR_CALLBACK_DECL
#   define PR_STATIC_CALLBACK(__x) static __x

#  elif defined(XP_OS2_VACPP)

#   define PR_EXPORT(__type) extern __type
#   define PR_EXPORT_DATA(__type) extern __type
#   define PR_IMPORT(__type) extern __type
#   define PR_IMPORT_DATA(__type) extern __type

#   define PR_EXTERN(__type) extern __type
#   define PR_IMPLEMENT(__type) __type
#   define PR_EXTERN_DATA(__type) extern __type
#   define PR_IMPLEMENT_DATA(__type) __type
#   define PR_CALLBACK _Optlink
#   define PR_CALLBACK_DECL
#   define PR_STATIC_CALLBACK(__x) static __x PR_CALLBACK

#  else /* Unix */

#   ifdef VBOX_HAVE_VISIBILITY_HIDDEN
#    define PR_EXPORT(__type) __attribute__((visibility("default"))) extern __type
#    define PR_EXPORT_DATA(__type) __attribute__((visibility("default"))) extern __type
#    define PR_IMPORT(__type) extern __type
#    define PR_IMPORT_DATA(__type) extern __type
#    define PR_EXTERN(__type) __attribute__((visibility("default"))) extern __type
#    define PR_IMPLEMENT(__type) __attribute__((visibility("default"))) __type
#    define PR_EXTERN_DATA(__type) __attribute__((visibility("default"))) extern __type
#    define PR_IMPLEMENT_DATA(__type) __attribute__((visibility("default"))) __type
#    define PR_CALLBACK
#    define PR_CALLBACK_DECL
#    define PR_STATIC_CALLBACK(__x) static __x
#   else
#    define PR_EXPORT(__type) extern __type
#    define PR_EXPORT_DATA(__type) extern __type
#    define PR_IMPORT(__type) extern __type
#    define PR_IMPORT_DATA(__type) extern __type
#    define PR_EXTERN(__type) extern __type
#    define PR_IMPLEMENT(__type) __type
#    define PR_EXTERN_DATA(__type) extern __type
#    define PR_IMPLEMENT_DATA(__type) __type
#    define PR_CALLBACK
#    define PR_CALLBACK_DECL
#    define PR_STATIC_CALLBACK(__x) static __x
#   endif
#  endif

#  if defined(_NSPR_BUILD_)
#   define NSPR_API(__type) PR_EXPORT(__type)
#   define NSPR_DATA_API(__type) PR_EXPORT_DATA(__type)
#  else
#   define NSPR_API(__type) PR_IMPORT(__type)
#   define NSPR_DATA_API(__type) PR_IMPORT_DATA(__type)
#  endif

typedef unsigned char PRUint8;
#  if (defined(HPUX) && defined(__cplusplus) \
       && !defined(__GNUC__) && __cplusplus < 199707L) \
      || (defined(SCO) && defined(__cplusplus) \
          && !defined(__GNUC__) && __cplusplus == 1L)
typedef char PRInt8;
#  else
typedef signed char PRInt8;
#  endif

#  define PR_INT8_MAX 127
#  define PR_INT8_MIN (-128)
#  define PR_UINT8_MAX 255U

typedef unsigned short PRUint16;
typedef short PRInt16;

#  define PR_INT16_MAX 32767
#  define PR_INT16_MIN (-32768)
#  define PR_UINT16_MAX 65535U

typedef unsigned int PRUint32;
typedef int PRInt32;
#  define PR_INT32(x)  x
#  define PR_UINT32(x) x ## U

#  define PR_INT32_MAX PR_INT32(2147483647)
#  define PR_INT32_MIN (-PR_INT32_MAX - 1)
#  define PR_UINT32_MAX PR_UINT32(4294967295)

typedef long PRInt64;
typedef unsigned long PRUint64;
typedef int PRIntn;
typedef unsigned int PRUintn;

typedef double          PRFloat64;
typedef size_t PRSize;

typedef ptrdiff_t PRPtrdiff;

typedef unsigned long PRUptrdiff;

typedef PRIntn PRBool;

#  define PR_TRUE 1
#  define PR_FALSE 0

typedef PRUint8 PRPackedBool;

/*
** Status code used by some routines that have a single point of failure or
** special status return.
*/
typedef enum { PR_FAILURE = -1, PR_SUCCESS = 0 } PRStatus;

#  ifndef __PRUNICHAR__
#   define __PRUNICHAR__
#   if defined(WIN32) || defined(XP_MAC)
typedef wchar_t PRUnichar;
#   else
typedef PRUint16 PRUnichar;
#   endif
#  endif

typedef long PRWord;
typedef unsigned long PRUword;

#  define nsnull 0
typedef PRUint32 nsresult;

#  if defined(__GNUC__) && (__GNUC__ > 2)
#   define NS_LIKELY(x)    (__builtin_expect((x), 1))
#   define NS_UNLIKELY(x)  (__builtin_expect((x), 0))
#  else
#   define NS_LIKELY(x)    (x)
#   define NS_UNLIKELY(x)  (x)
#  endif

#  define NS_FAILED(_nsresult) (NS_UNLIKELY((_nsresult) & 0x80000000))
#  define NS_SUCCEEDED(_nsresult) (NS_LIKELY(!((_nsresult) & 0x80000000)))

#  ifdef VBOX_WITH_XPCOM_NAMESPACE_CLEANUP
#   define PR_IntervalNow VBoxNsprPR_IntervalNow
#   define PR_TicksPerSecond VBoxNsprPR_TicksPerSecond
#   define PR_SecondsToInterval VBoxNsprPR_SecondsToInterval
#   define PR_MillisecondsToInterval VBoxNsprPR_MillisecondsToInterval
#   define PR_MicrosecondsToInterval VBoxNsprPR_MicrosecondsToInterval
#   define PR_IntervalToSeconds VBoxNsprPR_IntervalToSeconds
#   define PR_IntervalToMilliseconds VBoxNsprPR_IntervalToMilliseconds
#   define PR_IntervalToMicroseconds VBoxNsprPR_IntervalToMicroseconds
#   define PR_EnterMonitor VBoxNsprPR_EnterMonitor
#   define PR_ExitMonitor VBoxNsprPR_ExitMonitor
#   define PR_Notify VBoxNsprPR_Notify
#   define PR_NotifyAll VBoxNsprPR_NotifyAll
#   define PR_Wait VBoxNsprPR_Wait
#   define PR_NewMonitor VBoxNsprPR_NewMonitor
#   define PR_DestroyMonitor VBoxNsprPR_DestroyMonitor
#  endif /* VBOX_WITH_XPCOM_NAMESPACE_CLEANUP */

typedef PRUint32 PRIntervalTime;

#  define PR_INTERVAL_MIN 1000UL
#  define PR_INTERVAL_MAX 100000UL
#  define PR_INTERVAL_NO_WAIT 0UL
#  define PR_INTERVAL_NO_TIMEOUT 0xffffffffUL

NSPR_API(PRIntervalTime) PR_IntervalNow(void);
NSPR_API(PRUint32) PR_TicksPerSecond(void);
NSPR_API(PRIntervalTime) PR_SecondsToInterval(PRUint32 seconds);
NSPR_API(PRIntervalTime) PR_MillisecondsToInterval(PRUint32 milli);
NSPR_API(PRIntervalTime) PR_MicrosecondsToInterval(PRUint32 micro);
NSPR_API(PRUint32) PR_IntervalToSeconds(PRIntervalTime ticks);
NSPR_API(PRUint32) PR_IntervalToMilliseconds(PRIntervalTime ticks);
NSPR_API(PRUint32) PR_IntervalToMicroseconds(PRIntervalTime ticks);

typedef struct PRMonitor PRMonitor;

NSPR_API(PRMonitor*) PR_NewMonitor(void);
NSPR_API(void) PR_DestroyMonitor(PRMonitor *mon);
NSPR_API(void) PR_EnterMonitor(PRMonitor *mon);
NSPR_API(PRStatus) PR_ExitMonitor(PRMonitor *mon);
NSPR_API(PRStatus) PR_Wait(PRMonitor *mon, PRIntervalTime ticks);
NSPR_API(PRStatus) PR_Notify(PRMonitor *mon);
NSPR_API(PRStatus) PR_NotifyAll(PRMonitor *mon);

#  ifdef VBOX_WITH_XPCOM_NAMESPACE_CLEANUP
#   define PR_CreateThread VBoxNsprPR_CreateThread
#   define PR_JoinThread VBoxNsprPR_JoinThread
#   define PR_Sleep VBoxNsprPR_Sleep
#   define PR_GetCurrentThread VBoxNsprPR_GetCurrentThread
#   define PR_GetThreadState VBoxNsprPR_GetThreadState
#   define PR_SetThreadPrivate VBoxNsprPR_SetThreadPrivate
#   define PR_GetThreadPrivate VBoxNsprPR_GetThreadPrivate
#   define PR_NewThreadPrivateIndex VBoxNsprPR_NewThreadPrivateIndex
#   define PR_GetThreadPriority VBoxNsprPR_GetThreadPriority
#   define PR_SetThreadPriority VBoxNsprPR_SetThreadPriority
#   define PR_Interrupt VBoxNsprPR_Interrupt
#   define PR_ClearInterrupt VBoxNsprPR_ClearInterrupt
#   define PR_BlockInterrupt VBoxNsprPR_BlockInterrupt
#   define PR_UnblockInterrupt VBoxNsprPR_UnblockInterrupt
#   define PR_GetThreadScope VBoxNsprPR_GetThreadScope
#   define PR_GetThreadType VBoxNsprPR_GetThreadType
#  endif /* VBOX_WITH_XPCOM_NAMESPACE_CLEANUP */

typedef struct PRThread PRThread;
typedef struct PRThreadStack PRThreadStack;

typedef enum PRThreadType {
    PR_USER_THREAD,
    PR_SYSTEM_THREAD
} PRThreadType;

typedef enum PRThreadScope {
    PR_LOCAL_THREAD,
    PR_GLOBAL_THREAD,
    PR_GLOBAL_BOUND_THREAD
} PRThreadScope;

typedef enum PRThreadState {
    PR_JOINABLE_THREAD,
    PR_UNJOINABLE_THREAD
} PRThreadState;

typedef enum PRThreadPriority
{
    PR_PRIORITY_FIRST = 0,      /* just a placeholder */
    PR_PRIORITY_LOW = 0,        /* the lowest possible priority */
    PR_PRIORITY_NORMAL = 1,     /* most common expected priority */
    PR_PRIORITY_HIGH = 2,       /* slightly more aggressive scheduling */
    PR_PRIORITY_URGENT = 3,     /* it does little good to have more than one */
    PR_PRIORITY_LAST = 3        /* this is just a placeholder */
} PRThreadPriority;

NSPR_API(PRThread*) PR_CreateThread(PRThreadType type,
                     void (PR_CALLBACK *start)(void *arg),
                     void *arg,
                     PRThreadPriority priority,
                     PRThreadScope scope,
                     PRThreadState state,
                     PRUint32 stackSize);
NSPR_API(PRStatus) PR_JoinThread(PRThread *thread);
NSPR_API(PRThread*) PR_GetCurrentThread(void);
#  ifndef NO_NSPR_10_SUPPORT
#   define PR_CurrentThread() PR_GetCurrentThread() /* for nspr1.0 compat. */
#  endif /* NO_NSPR_10_SUPPORT */
NSPR_API(PRThreadPriority) PR_GetThreadPriority(const PRThread *thread);
NSPR_API(void) PR_SetThreadPriority(PRThread *thread, PRThreadPriority priority);

typedef void (PR_CALLBACK *PRThreadPrivateDTOR)(void *priv);

NSPR_API(PRStatus) PR_NewThreadPrivateIndex(
    PRUintn *newIndex, PRThreadPrivateDTOR destructor);
NSPR_API(PRStatus) PR_SetThreadPrivate(PRUintn tpdIndex, void *priv);
NSPR_API(void*) PR_GetThreadPrivate(PRUintn tpdIndex);
NSPR_API(PRStatus) PR_Interrupt(PRThread *thread);
NSPR_API(void) PR_ClearInterrupt(void);
NSPR_API(void) PR_BlockInterrupt(void);
NSPR_API(void) PR_UnblockInterrupt(void);
NSPR_API(PRStatus) PR_Sleep(PRIntervalTime ticks);
NSPR_API(PRThreadScope) PR_GetThreadScope(const PRThread *thread);
NSPR_API(PRThreadType) PR_GetThreadType(const PRThread *thread);
NSPR_API(PRThreadState) PR_GetThreadState(const PRThread *thread);

#  ifdef VBOX_WITH_XPCOM_NAMESPACE_CLEANUP
#   define PR_DestroyLock VBoxNsprPR_DestroyLock
#   define PR_Lock VBoxNsprPR_Lock
#   define PR_NewLock VBoxNsprPR_NewLock
#   define PR_Unlock VBoxNsprPR_Unlock
#  endif /* VBOX_WITH_XPCOM_NAMESPACE_CLEANUP */

typedef struct PRLock PRLock;

NSPR_API(PRLock*) PR_NewLock(void);
NSPR_API(void) PR_DestroyLock(PRLock *lock);
NSPR_API(void) PR_Lock(PRLock *lock);
NSPR_API(PRStatus) PR_Unlock(PRLock *lock);

#  ifdef VBOX_WITH_XPCOM_NAMESPACE_CLEANUP
#   define PR_NewCondVar VBoxNsprPR_NewCondVar
#   define PR_DestroyCondVar VBoxNsprPR_DestroyCondVar
#   define PR_WaitCondVar VBoxNsprPR_WaitCondVar
#   define PR_NotifyCondVar VBoxNsprPR_NotifyCondVar
#   define PR_NotifyAllCondVar VBoxNsprPR_NotifyAllCondVar
#  endif /* VBOX_WITH_XPCOM_NAMESPACE_CLEANUP */

typedef struct PRCondVar PRCondVar;

NSPR_API(PRCondVar*) PR_NewCondVar(PRLock *lock);
NSPR_API(void) PR_DestroyCondVar(PRCondVar *cvar);
NSPR_API(PRStatus) PR_WaitCondVar(PRCondVar *cvar, PRIntervalTime timeout);
NSPR_API(PRStatus) PR_NotifyCondVar(PRCondVar *cvar);
NSPR_API(PRStatus) PR_NotifyAllCondVar(PRCondVar *cvar);

typedef struct PRCListStr PRCList;

struct PRCListStr {
    PRCList *next;
    PRCList *prev;
};

#  ifdef VBOX_WITH_XPCOM_NAMESPACE_CLEANUP
#   define PL_DestroyEvent VBoxNsplPL_DestroyEvent
#   define PL_HandleEvent VBoxNsplPL_HandleEvent
#   define PL_InitEvent VBoxNsplPL_InitEvent
#   define PL_CreateEventQueue VBoxNsplPL_CreateEventQueue
#   define PL_CreateMonitoredEventQueue VBoxNsplPL_CreateMonitoredEventQueue
#   define PL_CreateNativeEventQueue VBoxNsplPL_CreateNativeEventQueue
#   define PL_DequeueEvent VBoxNsplPL_DequeueEvent
#   define PL_DestroyEventQueue VBoxNsplPL_DestroyEventQueue
#   define PL_EventAvailable VBoxNsplPL_EventAvailable
#   define PL_EventLoop VBoxNsplPL_EventLoop
#   define PL_GetEvent VBoxNsplPL_GetEvent
#   define PL_GetEventOwner VBoxNsplPL_GetEventOwner
#   define PL_GetEventQueueMonitor VBoxNsplPL_GetEventQueueMonitor
#   define PL_GetEventQueueSelectFD VBoxNsplPL_GetEventQueueSelectFD
#   define PL_MapEvents VBoxNsplPL_MapEvents
#   define PL_PostEvent VBoxNsplPL_PostEvent
#   define PL_PostSynchronousEvent VBoxNsplPL_PostSynchronousEvent
#   define PL_ProcessEventsBeforeID VBoxNsplPL_ProcessEventsBeforeID
#   define PL_ProcessPendingEvents VBoxNsplPL_ProcessPendingEvents
#   define PL_RegisterEventIDFunc VBoxNsplPL_RegisterEventIDFunc
#   define PL_RevokeEvents VBoxNsplPL_RevokeEvents
#   define PL_UnregisterEventIDFunc VBoxNsplPL_UnregisterEventIDFunc
#   define PL_WaitForEvent VBoxNsplPL_WaitForEvent
#   define PL_IsQueueNative VBoxNsplPL_IsQueueNative
#   define PL_IsQueueOnCurrentThread VBoxNsplPL_IsQueueOnCurrentThread
#   define PL_FavorPerformanceHint VBoxNsplPL_FavorPerformanceHint
#  endif /* VBOX_WITH_XPCOM_NAMESPACE_CLEANUP */

typedef struct PLEvent PLEvent;
typedef struct PLEventQueue PLEventQueue;

PR_EXTERN(PLEventQueue*)
PL_CreateEventQueue(const char* name, PRThread* handlerThread);
PR_EXTERN(PLEventQueue *)
    PL_CreateNativeEventQueue(
        const char *name,
        PRThread *handlerThread
    );
PR_EXTERN(PLEventQueue *)
    PL_CreateMonitoredEventQueue(
        const char *name,
        PRThread *handlerThread
    );
PR_EXTERN(void)
PL_DestroyEventQueue(PLEventQueue* self);
PR_EXTERN(PRMonitor*)
PL_GetEventQueueMonitor(PLEventQueue* self);

#  define PL_ENTER_EVENT_QUEUE_MONITOR(queue) \
    PR_EnterMonitor(PL_GetEventQueueMonitor(queue))

#  define PL_EXIT_EVENT_QUEUE_MONITOR(queue)  \
    PR_ExitMonitor(PL_GetEventQueueMonitor(queue))

PR_EXTERN(PRStatus) PL_PostEvent(PLEventQueue* self, PLEvent* event);
PR_EXTERN(void*) PL_PostSynchronousEvent(PLEventQueue* self, PLEvent* event);
PR_EXTERN(PLEvent*) PL_GetEvent(PLEventQueue* self);
PR_EXTERN(PRBool) PL_EventAvailable(PLEventQueue* self);

typedef void (PR_CALLBACK *PLEventFunProc)(PLEvent* event, void* data, PLEventQueue* queue);

PR_EXTERN(void) PL_MapEvents(PLEventQueue* self, PLEventFunProc fun, void* data);
PR_EXTERN(void) PL_RevokeEvents(PLEventQueue* self, void* owner);
PR_EXTERN(void) PL_ProcessPendingEvents(PLEventQueue* self);
PR_EXTERN(PLEvent*) PL_WaitForEvent(PLEventQueue* self);
PR_EXTERN(void) PL_EventLoop(PLEventQueue* self);
PR_EXTERN(PRInt32) PL_GetEventQueueSelectFD(PLEventQueue* self);
PR_EXTERN(PRBool) PL_IsQueueOnCurrentThread( PLEventQueue *queue );
PR_EXTERN(PRBool) PL_IsQueueNative(PLEventQueue *queue);

typedef void* (PR_CALLBACK *PLHandleEventProc)(PLEvent* self);
typedef void (PR_CALLBACK *PLDestroyEventProc)(PLEvent* self);
PR_EXTERN(void)
PL_InitEvent(PLEvent* self, void* owner,
             PLHandleEventProc handler,
             PLDestroyEventProc destructor);
PR_EXTERN(void*) PL_GetEventOwner(PLEvent* self);
PR_EXTERN(void) PL_HandleEvent(PLEvent* self);
PR_EXTERN(void) PL_DestroyEvent(PLEvent* self);
PR_EXTERN(void) PL_DequeueEvent(PLEvent* self, PLEventQueue* queue);
PR_EXTERN(void) PL_FavorPerformanceHint(PRBool favorPerformanceOverEventStarvation, PRUint32 starvationDelay);

struct PLEvent {
    PRCList             link;
    PLHandleEventProc   handler;
    PLDestroyEventProc  destructor;
    void*               owner;
    void*               synchronousResult;
    PRLock*             lock;
    PRCondVar*          condVar;
    PRBool              handled;
#  ifdef PL_POST_TIMINGS
    PRIntervalTime      postTime;
#  endif
#  ifdef XP_UNIX
    unsigned long       id;
#  endif /* XP_UNIX */
    /* other fields follow... */
};

#  if defined(XP_WIN) || defined(XP_OS2)

PR_EXTERN(HWND)
    PL_GetNativeEventReceiverWindow(
        PLEventQueue *eqp
    );
#  endif /* XP_WIN || XP_OS2 */

#  ifdef XP_UNIX

PR_EXTERN(PRInt32)
PL_ProcessEventsBeforeID(PLEventQueue *aSelf, unsigned long aID);

typedef unsigned long (PR_CALLBACK *PLGetEventIDFunc)(void *aClosure);

PR_EXTERN(void)
PL_RegisterEventIDFunc(PLEventQueue *aSelf, PLGetEventIDFunc aFunc,
                       void *aClosure);
PR_EXTERN(void) PL_UnregisterEventIDFunc(PLEventQueue *aSelf);

#  endif /* XP_UNIX */

/* Standard "it worked" return value */
#  define NS_OK                              0

#  define NS_ERROR_BASE                      ((nsresult) 0xC1F30000)

/* Returned when an instance is not initialized */
#  define NS_ERROR_NOT_INITIALIZED           (NS_ERROR_BASE + 1)

/* Returned when an instance is already initialized */
#  define NS_ERROR_ALREADY_INITIALIZED       (NS_ERROR_BASE + 2)

/* Returned by a not implemented function */
#  define NS_ERROR_NOT_IMPLEMENTED           ((nsresult) 0x80004001L)

/* Returned when a given interface is not supported. */
#  define NS_NOINTERFACE                     ((nsresult) 0x80004002L)
#  define NS_ERROR_NO_INTERFACE              NS_NOINTERFACE

#  define NS_ERROR_INVALID_POINTER           ((nsresult) 0x80004003L)
#  define NS_ERROR_NULL_POINTER              NS_ERROR_INVALID_POINTER

/* Returned when a function aborts */
#  define NS_ERROR_ABORT                     ((nsresult) 0x80004004L)

/* Returned when a function fails */
#  define NS_ERROR_FAILURE                   ((nsresult) 0x80004005L)

/* Returned when an unexpected error occurs */
#  define NS_ERROR_UNEXPECTED                ((nsresult) 0x8000ffffL)

/* Returned when a memory allocation fails */
#  define NS_ERROR_OUT_OF_MEMORY             ((nsresult) 0x8007000eL)

/* Returned when an illegal value is passed */
#  define NS_ERROR_ILLEGAL_VALUE             ((nsresult) 0x80070057L)
#  define NS_ERROR_INVALID_ARG               NS_ERROR_ILLEGAL_VALUE

/* Returned when a class doesn't allow aggregation */
#  define NS_ERROR_NO_AGGREGATION            ((nsresult) 0x80040110L)

/* Returned when an operation can't complete due to an unavailable resource */
#  define NS_ERROR_NOT_AVAILABLE             ((nsresult) 0x80040111L)

/* Returned when a class is not registered */
#  define NS_ERROR_FACTORY_NOT_REGISTERED    ((nsresult) 0x80040154L)

/* Returned when a class cannot be registered, but may be tried again later */
#  define NS_ERROR_FACTORY_REGISTER_AGAIN    ((nsresult) 0x80040155L)

/* Returned when a dynamically loaded factory couldn't be found */
#  define NS_ERROR_FACTORY_NOT_LOADED        ((nsresult) 0x800401f8L)

/* Returned when a factory doesn't support signatures */
#  define NS_ERROR_FACTORY_NO_SIGNATURE_SUPPORT \
                                           (NS_ERROR_BASE + 0x101)

/* Returned when a factory already is registered */
#  define NS_ERROR_FACTORY_EXISTS            (NS_ERROR_BASE + 0x100)


/**
 * An "interface id" which can be used to uniquely identify a given
 * interface.
 * A "unique identifier". This is modeled after OSF DCE UUIDs.
 */

struct nsID {
  PRUint32 m0;
  PRUint16 m1;
  PRUint16 m2;
  PRUint8 m3[8];
};

typedef struct nsID nsID;
typedef nsID nsIID;

struct nsISupports;   /* forward declaration */
struct nsIStackFrame; /* forward declaration */
struct nsIException;  /* forward declaration */
typedef struct nsISupports nsISupports;     /* forward declaration */
typedef struct nsIStackFrame nsIStackFrame; /* forward declaration */
typedef struct nsIException nsIException;   /* forward declaration */

/**
 * IID for the nsISupports interface
 * {00000000-0000-0000-c000-000000000046}
 *
 * To maintain binary compatibility with COM's IUnknown, we define the IID
 * of nsISupports to be the same as that of COM's IUnknown.
 */
#  define NS_ISUPPORTS_IID                                                      \
  { 0x00000000, 0x0000, 0x0000,                                               \
    {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46} }

/**
 * Reference count values
 *
 * This is the return type for AddRef() and Release() in nsISupports.
 * IUnknown of COM returns an unsigned long from equivalent functions.
 * The following ifdef exists to maintain binary compatibility with
 * IUnknown.
 */

/**
 * Basic component object model interface. Objects which implement
 * this interface support runtime interface discovery (QueryInterface)
 * and a reference counted memory model (AddRef/Release). This is
 * modelled after the win32 IUnknown API.
 */
struct nsISupports_vtbl {

  /**
   * @name Methods
   */

  /**
   * A run time mechanism for interface discovery.
   * @param aIID         [in]  A requested interface IID
   * @param aInstancePtr [out] A pointer to an interface pointer to
   *                           receive the result.
   * @return            NS_OK if the interface is supported by the associated
   *                          instance, NS_NOINTERFACE if it is not.
   * NS_ERROR_INVALID_POINTER if aInstancePtr is NULL.
   */
  nsresult (*QueryInterface)(nsISupports *pThis, const nsID *iid, void **resultp);
  /**
   * Increases the reference count for this interface.
   * The associated instance will not be deleted unless
   * the reference count is returned to zero.
   *
   * @return The resulting reference count.
   */
  nsresult (*AddRef)(nsISupports *pThis);

  /**
   * Decreases the reference count for this interface.
   * Generally, if the reference count returns to zero,
   * the associated instance is deleted.
   *
   * @return The resulting reference count.
   */
  nsresult (*Release)(nsISupports *pThis);

};

struct nsISupports {
    struct nsISupports_vtbl *vtbl;
};

/* starting interface:    nsIException */
#  define NS_IEXCEPTION_IID_STR "f3a8d3b4-c424-4edc-8bf6-8974c983ba78"

#  define NS_IEXCEPTION_IID \
  {0xf3a8d3b4, 0xc424, 0x4edc, \
    { 0x8b, 0xf6, 0x89, 0x74, 0xc9, 0x83, 0xba, 0x78 }}

struct nsIException_vtbl {

  /* Methods from the Class nsISupports */
  struct nsISupports_vtbl nsisupports;

  /* readonly attribute string message; */
  nsresult (*GetMessage)(nsIException *pThis, PRUnichar * *aMessage);

  /* readonly attribute nsresult (*result; */
  nsresult (*GetResult)(nsIException *pThis, nsresult *aResult);

  /* readonly attribute string name; */
  nsresult (*GetName)(nsIException *pThis, PRUnichar * *aName);

  /* readonly attribute string filename; */
  nsresult (*GetFilename)(nsIException *pThis, PRUnichar * *aFilename);

  /* readonly attribute PRUint32 lineNumber; */
  nsresult (*GetLineNumber)(nsIException *pThis, PRUint32 *aLineNumber);

  /* readonly attribute PRUint32 columnNumber; */
  nsresult (*GetColumnNumber)(nsIException *pThis, PRUint32 *aColumnNumber);

  /* readonly attribute nsIStackFrame location; */
  nsresult (*GetLocation)(nsIException *pThis, nsIStackFrame * *aLocation);

  /* readonly attribute nsIException inner; */
  nsresult (*GetInner)(nsIException *pThis, nsIException * *aInner);

  /* readonly attribute nsISupports data; */
  nsresult (*GetData)(nsIException *pThis, nsISupports * *aData);

  /* string toString (); */
  nsresult (*ToString)(nsIException *pThis, PRUnichar **_retval);
};

struct nsIException {
    struct nsIException_vtbl *vtbl;
};

/* starting interface:    nsIStackFrame */
#  define NS_ISTACKFRAME_IID_STR "91d82105-7c62-4f8b-9779-154277c0ee90"

#  define NS_ISTACKFRAME_IID \
  {0x91d82105, 0x7c62, 0x4f8b, \
    { 0x97, 0x79, 0x15, 0x42, 0x77, 0xc0, 0xee, 0x90 }}

struct nsIStackFrame_vtbl {

  /* Methods from the Class nsISupports */
  struct nsISupports_vtbl nsisupports;

  /* readonly attribute PRUint32 language; */
  nsresult (*GetLanguage)(nsIStackFrame *pThis, PRUint32 *aLanguage);

  /* readonly attribute string languageName; */
  nsresult (*GetLanguageName)(nsIStackFrame *pThis, PRUnichar * *aLanguageName);

  /* readonly attribute string filename; */
  nsresult (*GetFilename)(nsIStackFrame *pThis, PRUnichar * *aFilename);

  /* readonly attribute string name; */
  nsresult (*GetName)(nsIStackFrame *pThis, PRUnichar * *aName);

  /* readonly attribute PRInt32 lineNumber; */
  nsresult (*GetLineNumber)(nsIStackFrame *pThis, PRInt32 *aLineNumber);

  /* readonly attribute string sourceLine; */
  nsresult (*GetSourceLine)(nsIStackFrame *pThis, PRUnichar * *aSourceLine);

  /* readonly attribute nsIStackFrame caller; */
  nsresult (*GetCaller)(nsIStackFrame *pThis, nsIStackFrame * *aCaller);

  /* string toString (); */
  nsresult (*ToString)(nsIStackFrame *pThis, PRUnichar **_retval);
};

struct nsIStackFrame {
    struct nsIStackFrame_vtbl *vtbl;
};

/* starting interface:    nsIEventTarget */
#  define NS_IEVENTTARGET_IID_STR "ea99ad5b-cc67-4efb-97c9-2ef620a59f2a"

#  define NS_IEVENTTARGET_IID \
  {0xea99ad5b, 0xcc67, 0x4efb, \
    { 0x97, 0xc9, 0x2e, 0xf6, 0x20, 0xa5, 0x9f, 0x2a }}

struct nsIEventTarget;
typedef struct nsIEventTarget nsIEventTarget;

struct nsIEventTarget_vtbl {

    struct nsISupports_vtbl nsisupports;

    nsresult (*PostEvent)(nsIEventTarget *pThis, PLEvent * aEvent);

    nsresult (*IsOnCurrentThread)(nsIEventTarget *pThis, PRBool *_retval);

};

struct nsIEventTarget {
    struct nsIEventTarget_vtbl *vtbl;
};

/* starting interface:    nsIEventQueue */
#  define NS_IEVENTQUEUE_IID_STR "176afb41-00a4-11d3-9f2a-00400553eef0"

#  define NS_IEVENTQUEUE_IID \
  {0x176afb41, 0x00a4, 0x11d3, \
    { 0x9f, 0x2a, 0x00, 0x40, 0x05, 0x53, 0xee, 0xf0 }}

struct nsIEventQueue;
typedef struct nsIEventQueue nsIEventQueue;

struct nsIEventQueue_vtbl {

    struct nsIEventTarget_vtbl nsieventtarget;

    nsresult (*InitEvent)(nsIEventQueue *pThis, PLEvent * aEvent, void * owner, PLHandleEventProc handler, PLDestroyEventProc destructor);

    nsresult (*PostSynchronousEvent)(nsIEventQueue *pThis, PLEvent * aEvent, void * *aResult);

    nsresult (*PendingEvents)(nsIEventQueue *pThis, PRBool *_retval);

    nsresult (*ProcessPendingEvents)(nsIEventQueue *pThis);

    nsresult (*EventLoop)(nsIEventQueue *pThis);

    nsresult (*EventAvailable)(nsIEventQueue *pThis, PRBool *aResult);

    nsresult (*GetEvent)(nsIEventQueue *pThis, PLEvent * *_retval);

    nsresult (*HandleEvent)(nsIEventQueue *pThis, PLEvent * aEvent);

    nsresult (*WaitForEvent)(nsIEventQueue *pThis, PLEvent * *_retval);

    PRInt32 (*GetEventQueueSelectFD)(nsIEventQueue *pThis);

    nsresult (*Init)(nsIEventQueue *pThis, PRBool aNative);

    nsresult (*InitFromPRThread)(nsIEventQueue *pThis, PRThread * thread, PRBool aNative);

    nsresult (*InitFromPLQueue)(nsIEventQueue *pThis, PLEventQueue * aQueue);

    nsresult (*EnterMonitor)(nsIEventQueue *pThis);

    nsresult (*ExitMonitor)(nsIEventQueue *pThis);

    nsresult (*RevokeEvents)(nsIEventQueue *pThis, void * owner);

    nsresult (*GetPLEventQueue)(nsIEventQueue *pThis, PLEventQueue * *_retval);

    nsresult (*IsQueueNative)(nsIEventQueue *pThis, PRBool *_retval);

    nsresult (*StopAcceptingEvents)(nsIEventQueue *pThis);

};

struct nsIEventQueue {
    struct nsIEventQueue_vtbl *vtbl;
};


#  define VBOX_E_OBJECT_NOT_FOUND 0x80BB0001
#  define VBOX_E_INVALID_VM_STATE 0x80BB0002
#  define VBOX_E_VM_ERROR 0x80BB0003
#  define VBOX_E_FILE_ERROR 0x80BB0004
#  define VBOX_E_IPRT_ERROR 0x80BB0005
#  define VBOX_E_PDM_ERROR 0x80BB0006
#  define VBOX_E_INVALID_OBJECT_STATE 0x80BB0007
#  define VBOX_E_HOST_ERROR 0x80BB0008
#  define VBOX_E_NOT_SUPPORTED 0x80BB0009
#  define VBOX_E_XML_ERROR 0x80BB000A
#  define VBOX_E_INVALID_SESSION_STATE 0x80BB000B
#  define VBOX_E_OBJECT_IN_USE 0x80BB000C


struct IVirtualBoxErrorInfo;
struct INATNetwork;
struct IDHCPServer;
struct IVirtualBox;
struct IVFSExplorer;
struct IAppliance;
struct IVirtualSystemDescription;
struct IInternalMachineControl;
struct IBIOSSettings;
struct IPCIAddress;
struct IPCIDeviceAttachment;
struct IMachine;
struct IEmulatedUSB;
struct IVRDEServerInfo;
struct IConsole;
struct IHostNetworkInterface;
struct IHostVideoInputDevice;
struct IHost;
struct ISystemProperties;
struct IGuestOSType;
struct IAdditionsFacility;
struct IGuestSession;
struct IProcess;
struct IGuestProcess;
struct IDirectory;
struct IGuestDirectory;
struct IFile;
struct IGuestFile;
struct IFsObjInfo;
struct IGuestFsObjInfo;
struct IGuest;
struct IProgress;
struct ISnapshot;
struct IMediumAttachment;
struct IMedium;
struct IMediumFormat;
struct IToken;
struct IKeyboard;
struct IMouse;
struct IFramebuffer;
struct IFramebufferOverlay;
struct IDisplay;
struct INetworkAdapter;
struct ISerialPort;
struct IParallelPort;
struct IMachineDebugger;
struct IUSBDeviceFilters;
struct IUSBController;
struct IUSBDevice;
struct IUSBDeviceFilter;
struct IHostUSBDevice;
struct IHostUSBDeviceFilter;
struct IAudioAdapter;
struct IVRDEServer;
struct ISharedFolder;
struct IInternalSessionControl;
struct ISession;
struct IStorageController;
struct IManagedObjectRef;
struct IWebsessionManager;
struct IPerformanceMetric;
struct IPerformanceCollector;
struct INATEngine;
struct IExtPackPlugIn;
struct IExtPackBase;
struct IExtPack;
struct IExtPackFile;
struct IExtPackManager;
struct IBandwidthGroup;
struct IBandwidthControl;
struct IVirtualBoxClient;
struct IEventSource;
struct IEventListener;
struct IEvent;
struct IReusableEvent;
struct IMachineEvent;
struct IMachineStateChangedEvent;
struct IMachineDataChangedEvent;
struct IMediumRegisteredEvent;
struct IMachineRegisteredEvent;
struct ISessionStateChangedEvent;
struct IGuestPropertyChangedEvent;
struct ISnapshotEvent;
struct ISnapshotTakenEvent;
struct ISnapshotDeletedEvent;
struct ISnapshotChangedEvent;
struct IMousePointerShapeChangedEvent;
struct IMouseCapabilityChangedEvent;
struct IKeyboardLedsChangedEvent;
struct IStateChangedEvent;
struct IAdditionsStateChangedEvent;
struct INetworkAdapterChangedEvent;
struct ISerialPortChangedEvent;
struct IParallelPortChangedEvent;
struct IStorageControllerChangedEvent;
struct IMediumChangedEvent;
struct IClipboardModeChangedEvent;
struct IDragAndDropModeChangedEvent;
struct ICPUChangedEvent;
struct ICPUExecutionCapChangedEvent;
struct IGuestKeyboardEvent;
struct IGuestMouseEvent;
struct IGuestMultiTouchEvent;
struct IGuestSessionEvent;
struct IGuestSessionStateChangedEvent;
struct IGuestSessionRegisteredEvent;
struct IGuestProcessEvent;
struct IGuestProcessRegisteredEvent;
struct IGuestProcessStateChangedEvent;
struct IGuestProcessIOEvent;
struct IGuestProcessInputNotifyEvent;
struct IGuestProcessOutputEvent;
struct IGuestFileEvent;
struct IGuestFileRegisteredEvent;
struct IGuestFileStateChangedEvent;
struct IGuestFileIOEvent;
struct IGuestFileOffsetChangedEvent;
struct IGuestFileReadEvent;
struct IGuestFileWriteEvent;
struct IVRDEServerChangedEvent;
struct IVRDEServerInfoChangedEvent;
struct IVideoCaptureChangedEvent;
struct IUSBControllerChangedEvent;
struct IUSBDeviceStateChangedEvent;
struct ISharedFolderChangedEvent;
struct IRuntimeErrorEvent;
struct IEventSourceChangedEvent;
struct IExtraDataChangedEvent;
struct IVetoEvent;
struct IExtraDataCanChangeEvent;
struct ICanShowWindowEvent;
struct IShowWindowEvent;
struct INATRedirectEvent;
struct IHostPCIDevicePlugEvent;
struct IVBoxSVCAvailabilityChangedEvent;
struct IBandwidthGroupChangedEvent;
struct IGuestMonitorChangedEvent;
struct IGuestUserStateChangedEvent;
struct IStorageDeviceChangedEvent;
struct INATNetworkChangedEvent;
struct INATNetworkStartStopEvent;
struct INATNetworkAlterEvent;
struct INATNetworkCreationDeletionEvent;
struct INATNetworkSettingEvent;
struct INATNetworkPortForwardEvent;
struct IHostNameResolutionConfigurationChangeEvent;

typedef struct IVirtualBoxErrorInfo IVirtualBoxErrorInfo;
typedef struct INATNetwork INATNetwork;
typedef struct IDHCPServer IDHCPServer;
typedef struct IVirtualBox IVirtualBox;
typedef struct IVFSExplorer IVFSExplorer;
typedef struct IAppliance IAppliance;
typedef struct IVirtualSystemDescription IVirtualSystemDescription;
typedef struct IInternalMachineControl IInternalMachineControl;
typedef struct IBIOSSettings IBIOSSettings;
typedef struct IPCIAddress IPCIAddress;
typedef struct IPCIDeviceAttachment IPCIDeviceAttachment;
typedef struct IMachine IMachine;
typedef struct IEmulatedUSB IEmulatedUSB;
typedef struct IVRDEServerInfo IVRDEServerInfo;
typedef struct IConsole IConsole;
typedef struct IHostNetworkInterface IHostNetworkInterface;
typedef struct IHostVideoInputDevice IHostVideoInputDevice;
typedef struct IHost IHost;
typedef struct ISystemProperties ISystemProperties;
typedef struct IGuestOSType IGuestOSType;
typedef struct IAdditionsFacility IAdditionsFacility;
typedef struct IGuestSession IGuestSession;
typedef struct IProcess IProcess;
typedef struct IGuestProcess IGuestProcess;
typedef struct IDirectory IDirectory;
typedef struct IGuestDirectory IGuestDirectory;
typedef struct IFile IFile;
typedef struct IGuestFile IGuestFile;
typedef struct IFsObjInfo IFsObjInfo;
typedef struct IGuestFsObjInfo IGuestFsObjInfo;
typedef struct IGuest IGuest;
typedef struct IProgress IProgress;
typedef struct ISnapshot ISnapshot;
typedef struct IMediumAttachment IMediumAttachment;
typedef struct IMedium IMedium;
typedef struct IMediumFormat IMediumFormat;
typedef struct IToken IToken;
typedef struct IKeyboard IKeyboard;
typedef struct IMouse IMouse;
typedef struct IFramebuffer IFramebuffer;
typedef struct IFramebufferOverlay IFramebufferOverlay;
typedef struct IDisplay IDisplay;
typedef struct INetworkAdapter INetworkAdapter;
typedef struct ISerialPort ISerialPort;
typedef struct IParallelPort IParallelPort;
typedef struct IMachineDebugger IMachineDebugger;
typedef struct IUSBDeviceFilters IUSBDeviceFilters;
typedef struct IUSBController IUSBController;
typedef struct IUSBDevice IUSBDevice;
typedef struct IUSBDeviceFilter IUSBDeviceFilter;
typedef struct IHostUSBDevice IHostUSBDevice;
typedef struct IHostUSBDeviceFilter IHostUSBDeviceFilter;
typedef struct IAudioAdapter IAudioAdapter;
typedef struct IVRDEServer IVRDEServer;
typedef struct ISharedFolder ISharedFolder;
typedef struct IInternalSessionControl IInternalSessionControl;
typedef struct ISession ISession;
typedef struct IStorageController IStorageController;
typedef struct IManagedObjectRef IManagedObjectRef;
typedef struct IWebsessionManager IWebsessionManager;
typedef struct IPerformanceMetric IPerformanceMetric;
typedef struct IPerformanceCollector IPerformanceCollector;
typedef struct INATEngine INATEngine;
typedef struct IExtPackPlugIn IExtPackPlugIn;
typedef struct IExtPackBase IExtPackBase;
typedef struct IExtPack IExtPack;
typedef struct IExtPackFile IExtPackFile;
typedef struct IExtPackManager IExtPackManager;
typedef struct IBandwidthGroup IBandwidthGroup;
typedef struct IBandwidthControl IBandwidthControl;
typedef struct IVirtualBoxClient IVirtualBoxClient;
typedef struct IEventSource IEventSource;
typedef struct IEventListener IEventListener;
typedef struct IEvent IEvent;
typedef struct IReusableEvent IReusableEvent;
typedef struct IMachineEvent IMachineEvent;
typedef struct IMachineStateChangedEvent IMachineStateChangedEvent;
typedef struct IMachineDataChangedEvent IMachineDataChangedEvent;
typedef struct IMediumRegisteredEvent IMediumRegisteredEvent;
typedef struct IMachineRegisteredEvent IMachineRegisteredEvent;
typedef struct ISessionStateChangedEvent ISessionStateChangedEvent;
typedef struct IGuestPropertyChangedEvent IGuestPropertyChangedEvent;
typedef struct ISnapshotEvent ISnapshotEvent;
typedef struct ISnapshotTakenEvent ISnapshotTakenEvent;
typedef struct ISnapshotDeletedEvent ISnapshotDeletedEvent;
typedef struct ISnapshotChangedEvent ISnapshotChangedEvent;
typedef struct IMousePointerShapeChangedEvent IMousePointerShapeChangedEvent;
typedef struct IMouseCapabilityChangedEvent IMouseCapabilityChangedEvent;
typedef struct IKeyboardLedsChangedEvent IKeyboardLedsChangedEvent;
typedef struct IStateChangedEvent IStateChangedEvent;
typedef struct IAdditionsStateChangedEvent IAdditionsStateChangedEvent;
typedef struct INetworkAdapterChangedEvent INetworkAdapterChangedEvent;
typedef struct ISerialPortChangedEvent ISerialPortChangedEvent;
typedef struct IParallelPortChangedEvent IParallelPortChangedEvent;
typedef struct IStorageControllerChangedEvent IStorageControllerChangedEvent;
typedef struct IMediumChangedEvent IMediumChangedEvent;
typedef struct IClipboardModeChangedEvent IClipboardModeChangedEvent;
typedef struct IDragAndDropModeChangedEvent IDragAndDropModeChangedEvent;
typedef struct ICPUChangedEvent ICPUChangedEvent;
typedef struct ICPUExecutionCapChangedEvent ICPUExecutionCapChangedEvent;
typedef struct IGuestKeyboardEvent IGuestKeyboardEvent;
typedef struct IGuestMouseEvent IGuestMouseEvent;
typedef struct IGuestMultiTouchEvent IGuestMultiTouchEvent;
typedef struct IGuestSessionEvent IGuestSessionEvent;
typedef struct IGuestSessionStateChangedEvent IGuestSessionStateChangedEvent;
typedef struct IGuestSessionRegisteredEvent IGuestSessionRegisteredEvent;
typedef struct IGuestProcessEvent IGuestProcessEvent;
typedef struct IGuestProcessRegisteredEvent IGuestProcessRegisteredEvent;
typedef struct IGuestProcessStateChangedEvent IGuestProcessStateChangedEvent;
typedef struct IGuestProcessIOEvent IGuestProcessIOEvent;
typedef struct IGuestProcessInputNotifyEvent IGuestProcessInputNotifyEvent;
typedef struct IGuestProcessOutputEvent IGuestProcessOutputEvent;
typedef struct IGuestFileEvent IGuestFileEvent;
typedef struct IGuestFileRegisteredEvent IGuestFileRegisteredEvent;
typedef struct IGuestFileStateChangedEvent IGuestFileStateChangedEvent;
typedef struct IGuestFileIOEvent IGuestFileIOEvent;
typedef struct IGuestFileOffsetChangedEvent IGuestFileOffsetChangedEvent;
typedef struct IGuestFileReadEvent IGuestFileReadEvent;
typedef struct IGuestFileWriteEvent IGuestFileWriteEvent;
typedef struct IVRDEServerChangedEvent IVRDEServerChangedEvent;
typedef struct IVRDEServerInfoChangedEvent IVRDEServerInfoChangedEvent;
typedef struct IVideoCaptureChangedEvent IVideoCaptureChangedEvent;
typedef struct IUSBControllerChangedEvent IUSBControllerChangedEvent;
typedef struct IUSBDeviceStateChangedEvent IUSBDeviceStateChangedEvent;
typedef struct ISharedFolderChangedEvent ISharedFolderChangedEvent;
typedef struct IRuntimeErrorEvent IRuntimeErrorEvent;
typedef struct IEventSourceChangedEvent IEventSourceChangedEvent;
typedef struct IExtraDataChangedEvent IExtraDataChangedEvent;
typedef struct IVetoEvent IVetoEvent;
typedef struct IExtraDataCanChangeEvent IExtraDataCanChangeEvent;
typedef struct ICanShowWindowEvent ICanShowWindowEvent;
typedef struct IShowWindowEvent IShowWindowEvent;
typedef struct INATRedirectEvent INATRedirectEvent;
typedef struct IHostPCIDevicePlugEvent IHostPCIDevicePlugEvent;
typedef struct IVBoxSVCAvailabilityChangedEvent IVBoxSVCAvailabilityChangedEvent;
typedef struct IBandwidthGroupChangedEvent IBandwidthGroupChangedEvent;
typedef struct IGuestMonitorChangedEvent IGuestMonitorChangedEvent;
typedef struct IGuestUserStateChangedEvent IGuestUserStateChangedEvent;
typedef struct IStorageDeviceChangedEvent IStorageDeviceChangedEvent;
typedef struct INATNetworkChangedEvent INATNetworkChangedEvent;
typedef struct INATNetworkStartStopEvent INATNetworkStartStopEvent;
typedef struct INATNetworkAlterEvent INATNetworkAlterEvent;
typedef struct INATNetworkCreationDeletionEvent INATNetworkCreationDeletionEvent;
typedef struct INATNetworkSettingEvent INATNetworkSettingEvent;
typedef struct INATNetworkPortForwardEvent INATNetworkPortForwardEvent;
typedef struct IHostNameResolutionConfigurationChangeEvent IHostNameResolutionConfigurationChangeEvent;

/* Start of enum SettingsVersion Declaration */
#  define SETTINGSVERSION_IID_STR "d5b15ca7-3de7-46b2-a63a-ddcce42bfa3f"
#  define SETTINGSVERSION_IID { \
    0xd5b15ca7, 0x3de7, 0x46b2, \
    { 0xa6, 0x3a, 0xdd, 0xcc, 0xe4, 0x2b, 0xfa, 0x3f } \
}
enum SettingsVersion
{
    SettingsVersion_Null = 0,
    SettingsVersion_v1_0 = 1,
    SettingsVersion_v1_1 = 2,
    SettingsVersion_v1_2 = 3,
    SettingsVersion_v1_3pre = 4,
    SettingsVersion_v1_3 = 5,
    SettingsVersion_v1_4 = 6,
    SettingsVersion_v1_5 = 7,
    SettingsVersion_v1_6 = 8,
    SettingsVersion_v1_7 = 9,
    SettingsVersion_v1_8 = 10,
    SettingsVersion_v1_9 = 11,
    SettingsVersion_v1_10 = 12,
    SettingsVersion_v1_11 = 13,
    SettingsVersion_v1_12 = 14,
    SettingsVersion_v1_13 = 15,
    SettingsVersion_v1_14 = 16,
    SettingsVersion_Future = 99999
};
/* End of enum SettingsVersion Declaration */


/* Start of enum AccessMode Declaration */
#  define ACCESSMODE_IID_STR "1da0007c-ddf7-4be8-bcac-d84a1558785f"
#  define ACCESSMODE_IID { \
    0x1da0007c, 0xddf7, 0x4be8, \
    { 0xbc, 0xac, 0xd8, 0x4a, 0x15, 0x58, 0x78, 0x5f } \
}
enum AccessMode
{
    AccessMode_ReadOnly = 1,
    AccessMode_ReadWrite = 2
};
/* End of enum AccessMode Declaration */


/* Start of enum MachineState Declaration */
#  define MACHINESTATE_IID_STR "ec6c6a9e-113d-4ff4-b44f-0b69f21c97fe"
#  define MACHINESTATE_IID { \
    0xec6c6a9e, 0x113d, 0x4ff4, \
    { 0xb4, 0x4f, 0x0b, 0x69, 0xf2, 0x1c, 0x97, 0xfe } \
}
enum MachineState
{
    MachineState_Null = 0,
    MachineState_PoweredOff = 1,
    MachineState_Saved = 2,
    MachineState_Teleported = 3,
    MachineState_Aborted = 4,
    MachineState_Running = 5,
    MachineState_Paused = 6,
    MachineState_Stuck = 7,
    MachineState_Teleporting = 8,
    MachineState_LiveSnapshotting = 9,
    MachineState_Starting = 10,
    MachineState_Stopping = 11,
    MachineState_Saving = 12,
    MachineState_Restoring = 13,
    MachineState_TeleportingPausedVM = 14,
    MachineState_TeleportingIn = 15,
    MachineState_FaultTolerantSyncing = 16,
    MachineState_DeletingSnapshotOnline = 17,
    MachineState_DeletingSnapshotPaused = 18,
    MachineState_RestoringSnapshot = 19,
    MachineState_DeletingSnapshot = 20,
    MachineState_SettingUp = 21,
    MachineState_FirstOnline = 5,
    MachineState_LastOnline = 18,
    MachineState_FirstTransient = 8,
    MachineState_LastTransient = 21
};
/* End of enum MachineState Declaration */


/* Start of enum SessionState Declaration */
#  define SESSIONSTATE_IID_STR "cf2700c0-ea4b-47ae-9725-7810114b94d8"
#  define SESSIONSTATE_IID { \
    0xcf2700c0, 0xea4b, 0x47ae, \
    { 0x97, 0x25, 0x78, 0x10, 0x11, 0x4b, 0x94, 0xd8 } \
}
enum SessionState
{
    SessionState_Null = 0,
    SessionState_Unlocked = 1,
    SessionState_Locked = 2,
    SessionState_Spawning = 3,
    SessionState_Unlocking = 4
};
/* End of enum SessionState Declaration */


/* Start of enum CPUPropertyType Declaration */
#  define CPUPROPERTYTYPE_IID_STR "52bc41f4-a279-45da-88ab-3a1d86fb73eb"
#  define CPUPROPERTYTYPE_IID { \
    0x52bc41f4, 0xa279, 0x45da, \
    { 0x88, 0xab, 0x3a, 0x1d, 0x86, 0xfb, 0x73, 0xeb } \
}
enum CPUPropertyType
{
    CPUPropertyType_Null = 0,
    CPUPropertyType_PAE = 1,
    CPUPropertyType_Synthetic = 2,
    CPUPropertyType_LongMode = 3,
    CPUPropertyType_TripleFaultReset = 4
};
/* End of enum CPUPropertyType Declaration */


/* Start of enum HWVirtExPropertyType Declaration */
#  define HWVIRTEXPROPERTYTYPE_IID_STR "411ad0ea-aeeb-44cb-9d03-1624d0d025ac"
#  define HWVIRTEXPROPERTYTYPE_IID { \
    0x411ad0ea, 0xaeeb, 0x44cb, \
    { 0x9d, 0x03, 0x16, 0x24, 0xd0, 0xd0, 0x25, 0xac } \
}
enum HWVirtExPropertyType
{
    HWVirtExPropertyType_Null = 0,
    HWVirtExPropertyType_Enabled = 1,
    HWVirtExPropertyType_VPID = 2,
    HWVirtExPropertyType_NestedPaging = 3,
    HWVirtExPropertyType_UnrestrictedExecution = 4,
    HWVirtExPropertyType_LargePages = 5,
    HWVirtExPropertyType_Force = 6
};
/* End of enum HWVirtExPropertyType Declaration */


/* Start of enum FaultToleranceState Declaration */
#  define FAULTTOLERANCESTATE_IID_STR "5124f7ec-6b67-493c-9dee-ee45a44114e1"
#  define FAULTTOLERANCESTATE_IID { \
    0x5124f7ec, 0x6b67, 0x493c, \
    { 0x9d, 0xee, 0xee, 0x45, 0xa4, 0x41, 0x14, 0xe1 } \
}
enum FaultToleranceState
{
    FaultToleranceState_Inactive = 1,
    FaultToleranceState_Master = 2,
    FaultToleranceState_Standby = 3
};
/* End of enum FaultToleranceState Declaration */


/* Start of enum LockType Declaration */
#  define LOCKTYPE_IID_STR "168a6a8e-12fd-4878-a1f9-38a750a56089"
#  define LOCKTYPE_IID { \
    0x168a6a8e, 0x12fd, 0x4878, \
    { 0xa1, 0xf9, 0x38, 0xa7, 0x50, 0xa5, 0x60, 0x89 } \
}
enum LockType
{
    LockType_Write = 2,
    LockType_Shared = 1,
    LockType_VM = 3
};
/* End of enum LockType Declaration */


/* Start of enum SessionType Declaration */
#  define SESSIONTYPE_IID_STR "A13C02CB-0C2C-421E-8317-AC0E8AAA153A"
#  define SESSIONTYPE_IID { \
    0xA13C02CB, 0x0C2C, 0x421E, \
    { 0x83, 0x17, 0xAC, 0x0E, 0x8A, 0xAA, 0x15, 0x3A } \
}
enum SessionType
{
    SessionType_Null = 0,
    SessionType_WriteLock = 1,
    SessionType_Remote = 2,
    SessionType_Shared = 3
};
/* End of enum SessionType Declaration */


/* Start of enum DeviceType Declaration */
#  define DEVICETYPE_IID_STR "6d9420f7-0b56-4636-99f9-7346f1b01e57"
#  define DEVICETYPE_IID { \
    0x6d9420f7, 0x0b56, 0x4636, \
    { 0x99, 0xf9, 0x73, 0x46, 0xf1, 0xb0, 0x1e, 0x57 } \
}
enum DeviceType
{
    DeviceType_Null = 0,
    DeviceType_Floppy = 1,
    DeviceType_DVD = 2,
    DeviceType_HardDisk = 3,
    DeviceType_Network = 4,
    DeviceType_USB = 5,
    DeviceType_SharedFolder = 6
};
/* End of enum DeviceType Declaration */


/* Start of enum DeviceActivity Declaration */
#  define DEVICEACTIVITY_IID_STR "6FC8AEAA-130A-4eb5-8954-3F921422D707"
#  define DEVICEACTIVITY_IID { \
    0x6FC8AEAA, 0x130A, 0x4eb5, \
    { 0x89, 0x54, 0x3F, 0x92, 0x14, 0x22, 0xD7, 0x07 } \
}
enum DeviceActivity
{
    DeviceActivity_Null = 0,
    DeviceActivity_Idle = 1,
    DeviceActivity_Reading = 2,
    DeviceActivity_Writing = 3
};
/* End of enum DeviceActivity Declaration */


/* Start of enum ClipboardMode Declaration */
#  define CLIPBOARDMODE_IID_STR "33364716-4008-4701-8f14-be0fa3d62950"
#  define CLIPBOARDMODE_IID { \
    0x33364716, 0x4008, 0x4701, \
    { 0x8f, 0x14, 0xbe, 0x0f, 0xa3, 0xd6, 0x29, 0x50 } \
}
enum ClipboardMode
{
    ClipboardMode_Disabled = 0,
    ClipboardMode_HostToGuest = 1,
    ClipboardMode_GuestToHost = 2,
    ClipboardMode_Bidirectional = 3
};
/* End of enum ClipboardMode Declaration */


/* Start of enum DragAndDropMode Declaration */
#  define DRAGANDDROPMODE_IID_STR "b618ea0e-b6fb-4f8d-97f7-5e237e49b547"
#  define DRAGANDDROPMODE_IID { \
    0xb618ea0e, 0xb6fb, 0x4f8d, \
    { 0x97, 0xf7, 0x5e, 0x23, 0x7e, 0x49, 0xb5, 0x47 } \
}
enum DragAndDropMode
{
    DragAndDropMode_Disabled = 0,
    DragAndDropMode_HostToGuest = 1,
    DragAndDropMode_GuestToHost = 2,
    DragAndDropMode_Bidirectional = 3
};
/* End of enum DragAndDropMode Declaration */


/* Start of enum Scope Declaration */
#  define SCOPE_IID_STR "7c91096e-499e-4eca-9f9b-9001438d7855"
#  define SCOPE_IID { \
    0x7c91096e, 0x499e, 0x4eca, \
    { 0x9f, 0x9b, 0x90, 0x01, 0x43, 0x8d, 0x78, 0x55 } \
}
enum Scope
{
    Scope_Global = 0,
    Scope_Machine = 1,
    Scope_Session = 2
};
/* End of enum Scope Declaration */


/* Start of enum BIOSBootMenuMode Declaration */
#  define BIOSBOOTMENUMODE_IID_STR "ae4fb9f7-29d2-45b4-b2c7-d579603135d5"
#  define BIOSBOOTMENUMODE_IID { \
    0xae4fb9f7, 0x29d2, 0x45b4, \
    { 0xb2, 0xc7, 0xd5, 0x79, 0x60, 0x31, 0x35, 0xd5 } \
}
enum BIOSBootMenuMode
{
    BIOSBootMenuMode_Disabled = 0,
    BIOSBootMenuMode_MenuOnly = 1,
    BIOSBootMenuMode_MessageAndMenu = 2
};
/* End of enum BIOSBootMenuMode Declaration */


/* Start of enum ProcessorFeature Declaration */
#  define PROCESSORFEATURE_IID_STR "64c38e6b-8bcf-45ad-ac03-9b406287c5bf"
#  define PROCESSORFEATURE_IID { \
    0x64c38e6b, 0x8bcf, 0x45ad, \
    { 0xac, 0x03, 0x9b, 0x40, 0x62, 0x87, 0xc5, 0xbf } \
}
enum ProcessorFeature
{
    ProcessorFeature_HWVirtEx = 0,
    ProcessorFeature_PAE = 1,
    ProcessorFeature_LongMode = 2,
    ProcessorFeature_NestedPaging = 3
};
/* End of enum ProcessorFeature Declaration */


/* Start of enum FirmwareType Declaration */
#  define FIRMWARETYPE_IID_STR "b903f264-c230-483e-ac74-2b37ce60d371"
#  define FIRMWARETYPE_IID { \
    0xb903f264, 0xc230, 0x483e, \
    { 0xac, 0x74, 0x2b, 0x37, 0xce, 0x60, 0xd3, 0x71 } \
}
enum FirmwareType
{
    FirmwareType_BIOS = 1,
    FirmwareType_EFI = 2,
    FirmwareType_EFI32 = 3,
    FirmwareType_EFI64 = 4,
    FirmwareType_EFIDUAL = 5
};
/* End of enum FirmwareType Declaration */


/* Start of enum PointingHIDType Declaration */
#  define POINTINGHIDTYPE_IID_STR "19964e93-0050-45c4-9382-a7bccc53e666"
#  define POINTINGHIDTYPE_IID { \
    0x19964e93, 0x0050, 0x45c4, \
    { 0x93, 0x82, 0xa7, 0xbc, 0xcc, 0x53, 0xe6, 0x66 } \
}
enum PointingHIDType
{
    PointingHIDType_None = 1,
    PointingHIDType_PS2Mouse = 2,
    PointingHIDType_USBMouse = 3,
    PointingHIDType_USBTablet = 4,
    PointingHIDType_ComboMouse = 5,
    PointingHIDType_USBMultiTouch = 6
};
/* End of enum PointingHIDType Declaration */


/* Start of enum KeyboardHIDType Declaration */
#  define KEYBOARDHIDTYPE_IID_STR "383e43d7-5c7c-4ec8-9cb8-eda1bccd6699"
#  define KEYBOARDHIDTYPE_IID { \
    0x383e43d7, 0x5c7c, 0x4ec8, \
    { 0x9c, 0xb8, 0xed, 0xa1, 0xbc, 0xcd, 0x66, 0x99 } \
}
enum KeyboardHIDType
{
    KeyboardHIDType_None = 1,
    KeyboardHIDType_PS2Keyboard = 2,
    KeyboardHIDType_USBKeyboard = 3,
    KeyboardHIDType_ComboKeyboard = 4
};
/* End of enum KeyboardHIDType Declaration */


/* Start of enum DhcpOpt Declaration */
#  define DHCPOPT_IID_STR "40d99bd3-3ece-44d2-a07e-1085fe9c4f0b"
#  define DHCPOPT_IID { \
    0x40d99bd3, 0x3ece, 0x44d2, \
    { 0xa0, 0x7e, 0x10, 0x85, 0xfe, 0x9c, 0x4f, 0x0b } \
}
enum DhcpOpt
{
    DhcpOpt_SubnetMask = 1,
    DhcpOpt_TimeOffset = 2,
    DhcpOpt_Router = 3,
    DhcpOpt_TimeServer = 4,
    DhcpOpt_NameServer = 5,
    DhcpOpt_DomainNameServer = 6,
    DhcpOpt_LogServer = 7,
    DhcpOpt_Cookie = 8,
    DhcpOpt_LPRServer = 9,
    DhcpOpt_ImpressServer = 10,
    DhcpOpt_ResourseLocationServer = 11,
    DhcpOpt_HostName = 12,
    DhcpOpt_BootFileSize = 13,
    DhcpOpt_MeritDumpFile = 14,
    DhcpOpt_DomainName = 15,
    DhcpOpt_SwapServer = 16,
    DhcpOpt_RootPath = 17,
    DhcpOpt_ExtensionPath = 18,
    DhcpOpt_IPForwardingEnableDisable = 19,
    DhcpOpt_NonLocalSourceRoutingEnableDisable = 20,
    DhcpOpt_PolicyFilter = 21,
    DhcpOpt_MaximumDatagramReassemblySize = 22,
    DhcpOpt_DefaultIPTime2Live = 23,
    DhcpOpt_PathMTUAgingTimeout = 24,
    DhcpOpt_IPLayerParametersPerInterface = 25,
    DhcpOpt_InterfaceMTU = 26,
    DhcpOpt_AllSubnetsAreLocal = 27,
    DhcpOpt_BroadcastAddress = 28,
    DhcpOpt_PerformMaskDiscovery = 29,
    DhcpOpt_MaskSupplier = 30,
    DhcpOpt_PerformRouteDiscovery = 31,
    DhcpOpt_RouterSolicitationAddress = 32,
    DhcpOpt_StaticRoute = 33,
    DhcpOpt_TrailerEncapsulation = 34,
    DhcpOpt_ARPCacheTimeout = 35,
    DhcpOpt_EthernetEncapsulation = 36,
    DhcpOpt_TCPDefaultTTL = 37,
    DhcpOpt_TCPKeepAliveInterval = 38,
    DhcpOpt_TCPKeepAliveGarbage = 39,
    DhcpOpt_NetworkInformationServiceDomain = 40,
    DhcpOpt_NetworkInformationServiceServers = 41,
    DhcpOpt_NetworkTimeProtocolServers = 42,
    DhcpOpt_VendorSpecificInformation = 43,
    DhcpOpt_Option_44 = 44,
    DhcpOpt_Option_45 = 45,
    DhcpOpt_Option_46 = 46,
    DhcpOpt_Option_47 = 47,
    DhcpOpt_Option_48 = 48,
    DhcpOpt_Option_49 = 49,
    DhcpOpt_IPAddressLeaseTime = 51,
    DhcpOpt_Option_64 = 64,
    DhcpOpt_Option_65 = 65,
    DhcpOpt_TFTPServerName = 66,
    DhcpOpt_BootfileName = 67,
    DhcpOpt_Option_68 = 68,
    DhcpOpt_Option_69 = 69,
    DhcpOpt_Option_70 = 70,
    DhcpOpt_Option_71 = 71,
    DhcpOpt_Option_72 = 72,
    DhcpOpt_Option_73 = 73,
    DhcpOpt_Option_74 = 74,
    DhcpOpt_Option_75 = 75,
    DhcpOpt_Option_119 = 119
};
/* End of enum DhcpOpt Declaration */


/* Start of enum VFSType Declaration */
#  define VFSTYPE_IID_STR "813999ba-b949-48a8-9230-aadc6285e2f2"
#  define VFSTYPE_IID { \
    0x813999ba, 0xb949, 0x48a8, \
    { 0x92, 0x30, 0xaa, 0xdc, 0x62, 0x85, 0xe2, 0xf2 } \
}
enum VFSType
{
    VFSType_File = 1,
    VFSType_Cloud = 2,
    VFSType_S3 = 3,
    VFSType_WebDav = 4
};
/* End of enum VFSType Declaration */


/* Start of enum VFSFileType Declaration */
#  define VFSFILETYPE_IID_STR "714333cd-44e2-415f-a245-d378fa9b1242"
#  define VFSFILETYPE_IID { \
    0x714333cd, 0x44e2, 0x415f, \
    { 0xa2, 0x45, 0xd3, 0x78, 0xfa, 0x9b, 0x12, 0x42 } \
}
enum VFSFileType
{
    VFSFileType_Unknown = 1,
    VFSFileType_Fifo = 2,
    VFSFileType_DevChar = 3,
    VFSFileType_Directory = 4,
    VFSFileType_DevBlock = 5,
    VFSFileType_File = 6,
    VFSFileType_SymLink = 7,
    VFSFileType_Socket = 8,
    VFSFileType_WhiteOut = 9
};
/* End of enum VFSFileType Declaration */


/* Start of enum ImportOptions Declaration */
#  define IMPORTOPTIONS_IID_STR "0a981523-3b20-4004-8ee3-dfd322202ace"
#  define IMPORTOPTIONS_IID { \
    0x0a981523, 0x3b20, 0x4004, \
    { 0x8e, 0xe3, 0xdf, 0xd3, 0x22, 0x20, 0x2a, 0xce } \
}
enum ImportOptions
{
    ImportOptions_KeepAllMACs = 1,
    ImportOptions_KeepNATMACs = 2
};
/* End of enum ImportOptions Declaration */


/* Start of enum ExportOptions Declaration */
#  define EXPORTOPTIONS_IID_STR "8f45eb08-fd34-41ee-af95-a880bdee5554"
#  define EXPORTOPTIONS_IID { \
    0x8f45eb08, 0xfd34, 0x41ee, \
    { 0xaf, 0x95, 0xa8, 0x80, 0xbd, 0xee, 0x55, 0x54 } \
}
enum ExportOptions
{
    ExportOptions_CreateManifest = 1,
    ExportOptions_ExportDVDImages = 2
};
/* End of enum ExportOptions Declaration */


/* Start of enum VirtualSystemDescriptionType Declaration */
#  define VIRTUALSYSTEMDESCRIPTIONTYPE_IID_STR "303c0900-a746-4612-8c67-79003e91f459"
#  define VIRTUALSYSTEMDESCRIPTIONTYPE_IID { \
    0x303c0900, 0xa746, 0x4612, \
    { 0x8c, 0x67, 0x79, 0x00, 0x3e, 0x91, 0xf4, 0x59 } \
}
enum VirtualSystemDescriptionType
{
    VirtualSystemDescriptionType_Ignore = 1,
    VirtualSystemDescriptionType_OS = 2,
    VirtualSystemDescriptionType_Name = 3,
    VirtualSystemDescriptionType_Product = 4,
    VirtualSystemDescriptionType_Vendor = 5,
    VirtualSystemDescriptionType_Version = 6,
    VirtualSystemDescriptionType_ProductUrl = 7,
    VirtualSystemDescriptionType_VendorUrl = 8,
    VirtualSystemDescriptionType_Description = 9,
    VirtualSystemDescriptionType_License = 10,
    VirtualSystemDescriptionType_Miscellaneous = 11,
    VirtualSystemDescriptionType_CPU = 12,
    VirtualSystemDescriptionType_Memory = 13,
    VirtualSystemDescriptionType_HardDiskControllerIDE = 14,
    VirtualSystemDescriptionType_HardDiskControllerSATA = 15,
    VirtualSystemDescriptionType_HardDiskControllerSCSI = 16,
    VirtualSystemDescriptionType_HardDiskControllerSAS = 17,
    VirtualSystemDescriptionType_HardDiskImage = 18,
    VirtualSystemDescriptionType_Floppy = 19,
    VirtualSystemDescriptionType_CDROM = 20,
    VirtualSystemDescriptionType_NetworkAdapter = 21,
    VirtualSystemDescriptionType_USBController = 22,
    VirtualSystemDescriptionType_SoundCard = 23,
    VirtualSystemDescriptionType_SettingsFile = 24
};
/* End of enum VirtualSystemDescriptionType Declaration */


/* Start of enum VirtualSystemDescriptionValueType Declaration */
#  define VIRTUALSYSTEMDESCRIPTIONVALUETYPE_IID_STR "56d9403f-3425-4118-9919-36f2a9b8c77c"
#  define VIRTUALSYSTEMDESCRIPTIONVALUETYPE_IID { \
    0x56d9403f, 0x3425, 0x4118, \
    { 0x99, 0x19, 0x36, 0xf2, 0xa9, 0xb8, 0xc7, 0x7c } \
}
enum VirtualSystemDescriptionValueType
{
    VirtualSystemDescriptionValueType_Reference = 1,
    VirtualSystemDescriptionValueType_Original = 2,
    VirtualSystemDescriptionValueType_Auto = 3,
    VirtualSystemDescriptionValueType_ExtraConfig = 4
};
/* End of enum VirtualSystemDescriptionValueType Declaration */


/* Start of enum GraphicsControllerType Declaration */
#  define GRAPHICSCONTROLLERTYPE_IID_STR "79c96ca0-9f39-4900-948e-68c41cbe127a"
#  define GRAPHICSCONTROLLERTYPE_IID { \
    0x79c96ca0, 0x9f39, 0x4900, \
    { 0x94, 0x8e, 0x68, 0xc4, 0x1c, 0xbe, 0x12, 0x7a } \
}
enum GraphicsControllerType
{
    GraphicsControllerType_Null = 0,
    GraphicsControllerType_VBoxVGA = 1
};
/* End of enum GraphicsControllerType Declaration */


/* Start of enum CleanupMode Declaration */
#  define CLEANUPMODE_IID_STR "67897c50-7cca-47a9-83f6-ce8fd8eb5441"
#  define CLEANUPMODE_IID { \
    0x67897c50, 0x7cca, 0x47a9, \
    { 0x83, 0xf6, 0xce, 0x8f, 0xd8, 0xeb, 0x54, 0x41 } \
}
enum CleanupMode
{
    CleanupMode_UnregisterOnly = 1,
    CleanupMode_DetachAllReturnNone = 2,
    CleanupMode_DetachAllReturnHardDisksOnly = 3,
    CleanupMode_Full = 4
};
/* End of enum CleanupMode Declaration */


/* Start of enum CloneMode Declaration */
#  define CLONEMODE_IID_STR "A7A159FE-5096-4B8D-8C3C-D033CB0B35A8"
#  define CLONEMODE_IID { \
    0xA7A159FE, 0x5096, 0x4B8D, \
    { 0x8C, 0x3C, 0xD0, 0x33, 0xCB, 0x0B, 0x35, 0xA8 } \
}
enum CloneMode
{
    CloneMode_MachineState = 1,
    CloneMode_MachineAndChildStates = 2,
    CloneMode_AllStates = 3
};
/* End of enum CloneMode Declaration */


/* Start of enum CloneOptions Declaration */
#  define CLONEOPTIONS_IID_STR "22243f8e-96ab-497c-8cf0-f40a566c630b"
#  define CLONEOPTIONS_IID { \
    0x22243f8e, 0x96ab, 0x497c, \
    { 0x8c, 0xf0, 0xf4, 0x0a, 0x56, 0x6c, 0x63, 0x0b } \
}
enum CloneOptions
{
    CloneOptions_Link = 1,
    CloneOptions_KeepAllMACs = 2,
    CloneOptions_KeepNATMACs = 3,
    CloneOptions_KeepDiskNames = 4
};
/* End of enum CloneOptions Declaration */


/* Start of enum AutostopType Declaration */
#  define AUTOSTOPTYPE_IID_STR "6bb96740-cf34-470d-aab2-2cd48ea2e10e"
#  define AUTOSTOPTYPE_IID { \
    0x6bb96740, 0xcf34, 0x470d, \
    { 0xaa, 0xb2, 0x2c, 0xd4, 0x8e, 0xa2, 0xe1, 0x0e } \
}
enum AutostopType
{
    AutostopType_Disabled = 1,
    AutostopType_SaveState = 2,
    AutostopType_PowerOff = 3,
    AutostopType_AcpiShutdown = 4
};
/* End of enum AutostopType Declaration */


/* Start of enum HostNetworkInterfaceMediumType Declaration */
#  define HOSTNETWORKINTERFACEMEDIUMTYPE_IID_STR "1aa54aaf-2497-45a2-bfb1-8eb225e93d5b"
#  define HOSTNETWORKINTERFACEMEDIUMTYPE_IID { \
    0x1aa54aaf, 0x2497, 0x45a2, \
    { 0xbf, 0xb1, 0x8e, 0xb2, 0x25, 0xe9, 0x3d, 0x5b } \
}
enum HostNetworkInterfaceMediumType
{
    HostNetworkInterfaceMediumType_Unknown = 0,
    HostNetworkInterfaceMediumType_Ethernet = 1,
    HostNetworkInterfaceMediumType_PPP = 2,
    HostNetworkInterfaceMediumType_SLIP = 3
};
/* End of enum HostNetworkInterfaceMediumType Declaration */


/* Start of enum HostNetworkInterfaceStatus Declaration */
#  define HOSTNETWORKINTERFACESTATUS_IID_STR "CC474A69-2710-434B-8D99-C38E5D5A6F41"
#  define HOSTNETWORKINTERFACESTATUS_IID { \
    0xCC474A69, 0x2710, 0x434B, \
    { 0x8D, 0x99, 0xC3, 0x8E, 0x5D, 0x5A, 0x6F, 0x41 } \
}
enum HostNetworkInterfaceStatus
{
    HostNetworkInterfaceStatus_Unknown = 0,
    HostNetworkInterfaceStatus_Up = 1,
    HostNetworkInterfaceStatus_Down = 2
};
/* End of enum HostNetworkInterfaceStatus Declaration */


/* Start of enum HostNetworkInterfaceType Declaration */
#  define HOSTNETWORKINTERFACETYPE_IID_STR "67431b00-9946-48a2-bc02-b25c5919f4f3"
#  define HOSTNETWORKINTERFACETYPE_IID { \
    0x67431b00, 0x9946, 0x48a2, \
    { 0xbc, 0x02, 0xb2, 0x5c, 0x59, 0x19, 0xf4, 0xf3 } \
}
enum HostNetworkInterfaceType
{
    HostNetworkInterfaceType_Bridged = 1,
    HostNetworkInterfaceType_HostOnly = 2
};
/* End of enum HostNetworkInterfaceType Declaration */


/* Start of enum AdditionsFacilityType Declaration */
#  define ADDITIONSFACILITYTYPE_IID_STR "98f7f957-89fb-49b6-a3b1-31e3285eb1d8"
#  define ADDITIONSFACILITYTYPE_IID { \
    0x98f7f957, 0x89fb, 0x49b6, \
    { 0xa3, 0xb1, 0x31, 0xe3, 0x28, 0x5e, 0xb1, 0xd8 } \
}
enum AdditionsFacilityType
{
    AdditionsFacilityType_None = 0,
    AdditionsFacilityType_VBoxGuestDriver = 20,
    AdditionsFacilityType_AutoLogon = 90,
    AdditionsFacilityType_VBoxService = 100,
    AdditionsFacilityType_VBoxTrayClient = 101,
    AdditionsFacilityType_Seamless = 1000,
    AdditionsFacilityType_Graphics = 1100,
    AdditionsFacilityType_All = 2147483646
};
/* End of enum AdditionsFacilityType Declaration */


/* Start of enum AdditionsFacilityClass Declaration */
#  define ADDITIONSFACILITYCLASS_IID_STR "446451b2-c88d-4e5d-84c9-91bc7f533f5f"
#  define ADDITIONSFACILITYCLASS_IID { \
    0x446451b2, 0xc88d, 0x4e5d, \
    { 0x84, 0xc9, 0x91, 0xbc, 0x7f, 0x53, 0x3f, 0x5f } \
}
enum AdditionsFacilityClass
{
    AdditionsFacilityClass_None = 0,
    AdditionsFacilityClass_Driver = 10,
    AdditionsFacilityClass_Service = 30,
    AdditionsFacilityClass_Program = 50,
    AdditionsFacilityClass_Feature = 100,
    AdditionsFacilityClass_ThirdParty = 999,
    AdditionsFacilityClass_All = 2147483646
};
/* End of enum AdditionsFacilityClass Declaration */


/* Start of enum AdditionsFacilityStatus Declaration */
#  define ADDITIONSFACILITYSTATUS_IID_STR "ce06f9e1-394e-4fe9-9368-5a88c567dbde"
#  define ADDITIONSFACILITYSTATUS_IID { \
    0xce06f9e1, 0x394e, 0x4fe9, \
    { 0x93, 0x68, 0x5a, 0x88, 0xc5, 0x67, 0xdb, 0xde } \
}
enum AdditionsFacilityStatus
{
    AdditionsFacilityStatus_Inactive = 0,
    AdditionsFacilityStatus_Paused = 1,
    AdditionsFacilityStatus_PreInit = 20,
    AdditionsFacilityStatus_Init = 30,
    AdditionsFacilityStatus_Active = 50,
    AdditionsFacilityStatus_Terminating = 100,
    AdditionsFacilityStatus_Terminated = 101,
    AdditionsFacilityStatus_Failed = 800,
    AdditionsFacilityStatus_Unknown = 999
};
/* End of enum AdditionsFacilityStatus Declaration */


/* Start of enum AdditionsRunLevelType Declaration */
#  define ADDITIONSRUNLEVELTYPE_IID_STR "a25417ee-a9dd-4f5b-b0dc-377860087754"
#  define ADDITIONSRUNLEVELTYPE_IID { \
    0xa25417ee, 0xa9dd, 0x4f5b, \
    { 0xb0, 0xdc, 0x37, 0x78, 0x60, 0x08, 0x77, 0x54 } \
}
enum AdditionsRunLevelType
{
    AdditionsRunLevelType_None = 0,
    AdditionsRunLevelType_System = 1,
    AdditionsRunLevelType_Userland = 2,
    AdditionsRunLevelType_Desktop = 3
};
/* End of enum AdditionsRunLevelType Declaration */


/* Start of enum AdditionsUpdateFlag Declaration */
#  define ADDITIONSUPDATEFLAG_IID_STR "726a818d-18d6-4389-94e8-3e9e6826171a"
#  define ADDITIONSUPDATEFLAG_IID { \
    0x726a818d, 0x18d6, 0x4389, \
    { 0x94, 0xe8, 0x3e, 0x9e, 0x68, 0x26, 0x17, 0x1a } \
}
enum AdditionsUpdateFlag
{
    AdditionsUpdateFlag_None = 0,
    AdditionsUpdateFlag_WaitForUpdateStartOnly = 1
};
/* End of enum AdditionsUpdateFlag Declaration */


/* Start of enum GuestSessionStatus Declaration */
#  define GUESTSESSIONSTATUS_IID_STR "ac2669da-4624-44f2-85b5-0b0bfb8d8673"
#  define GUESTSESSIONSTATUS_IID { \
    0xac2669da, 0x4624, 0x44f2, \
    { 0x85, 0xb5, 0x0b, 0x0b, 0xfb, 0x8d, 0x86, 0x73 } \
}
enum GuestSessionStatus
{
    GuestSessionStatus_Undefined = 0,
    GuestSessionStatus_Starting = 10,
    GuestSessionStatus_Started = 100,
    GuestSessionStatus_Terminating = 480,
    GuestSessionStatus_Terminated = 500,
    GuestSessionStatus_TimedOutKilled = 512,
    GuestSessionStatus_TimedOutAbnormally = 513,
    GuestSessionStatus_Down = 600,
    GuestSessionStatus_Error = 800
};
/* End of enum GuestSessionStatus Declaration */


/* Start of enum GuestSessionWaitForFlag Declaration */
#  define GUESTSESSIONWAITFORFLAG_IID_STR "bb7a372a-f635-4e11-a81a-e707f3a52ef5"
#  define GUESTSESSIONWAITFORFLAG_IID { \
    0xbb7a372a, 0xf635, 0x4e11, \
    { 0xa8, 0x1a, 0xe7, 0x07, 0xf3, 0xa5, 0x2e, 0xf5 } \
}
enum GuestSessionWaitForFlag
{
    GuestSessionWaitForFlag_None = 0,
    GuestSessionWaitForFlag_Start = 1,
    GuestSessionWaitForFlag_Terminate = 2,
    GuestSessionWaitForFlag_Status = 4
};
/* End of enum GuestSessionWaitForFlag Declaration */


/* Start of enum GuestSessionWaitResult Declaration */
#  define GUESTSESSIONWAITRESULT_IID_STR "c0f6a8a5-fdb6-42bf-a582-56c6f82bcd2d"
#  define GUESTSESSIONWAITRESULT_IID { \
    0xc0f6a8a5, 0xfdb6, 0x42bf, \
    { 0xa5, 0x82, 0x56, 0xc6, 0xf8, 0x2b, 0xcd, 0x2d } \
}
enum GuestSessionWaitResult
{
    GuestSessionWaitResult_None = 0,
    GuestSessionWaitResult_Start = 1,
    GuestSessionWaitResult_Terminate = 2,
    GuestSessionWaitResult_Status = 3,
    GuestSessionWaitResult_Error = 4,
    GuestSessionWaitResult_Timeout = 5,
    GuestSessionWaitResult_WaitFlagNotSupported = 6
};
/* End of enum GuestSessionWaitResult Declaration */


/* Start of enum GuestUserState Declaration */
#  define GUESTUSERSTATE_IID_STR "b2a82b02-fd3d-4fc2-ba84-6ba5ac8be198"
#  define GUESTUSERSTATE_IID { \
    0xb2a82b02, 0xfd3d, 0x4fc2, \
    { 0xba, 0x84, 0x6b, 0xa5, 0xac, 0x8b, 0xe1, 0x98 } \
}
enum GuestUserState
{
    GuestUserState_Unknown = 0,
    GuestUserState_LoggedIn = 1,
    GuestUserState_LoggedOut = 2,
    GuestUserState_Locked = 3,
    GuestUserState_Unlocked = 4,
    GuestUserState_Disabled = 5,
    GuestUserState_Idle = 6,
    GuestUserState_InUse = 7,
    GuestUserState_Created = 8,
    GuestUserState_Deleted = 9,
    GuestUserState_SessionChanged = 10,
    GuestUserState_CredentialsChanged = 11,
    GuestUserState_RoleChanged = 12,
    GuestUserState_GroupAdded = 13,
    GuestUserState_GroupRemoved = 14,
    GuestUserState_Elevated = 15
};
/* End of enum GuestUserState Declaration */


/* Start of enum FileSeekType Declaration */
#  define FILESEEKTYPE_IID_STR "1b73f4f3-3515-4073-a506-76878d9e2541"
#  define FILESEEKTYPE_IID { \
    0x1b73f4f3, 0x3515, 0x4073, \
    { 0xa5, 0x06, 0x76, 0x87, 0x8d, 0x9e, 0x25, 0x41 } \
}
enum FileSeekType
{
    FileSeekType_Set = 0,
    FileSeekType_Current = 1
};
/* End of enum FileSeekType Declaration */


/* Start of enum ProcessInputFlag Declaration */
#  define PROCESSINPUTFLAG_IID_STR "5d38c1dd-2604-4ddf-92e5-0c0cdd3bdbd5"
#  define PROCESSINPUTFLAG_IID { \
    0x5d38c1dd, 0x2604, 0x4ddf, \
    { 0x92, 0xe5, 0x0c, 0x0c, 0xdd, 0x3b, 0xdb, 0xd5 } \
}
enum ProcessInputFlag
{
    ProcessInputFlag_None = 0,
    ProcessInputFlag_EndOfFile = 1
};
/* End of enum ProcessInputFlag Declaration */


/* Start of enum ProcessOutputFlag Declaration */
#  define PROCESSOUTPUTFLAG_IID_STR "9979e85a-52bb-40b7-870c-57115e27e0f1"
#  define PROCESSOUTPUTFLAG_IID { \
    0x9979e85a, 0x52bb, 0x40b7, \
    { 0x87, 0x0c, 0x57, 0x11, 0x5e, 0x27, 0xe0, 0xf1 } \
}
enum ProcessOutputFlag
{
    ProcessOutputFlag_None = 0,
    ProcessOutputFlag_StdErr = 1
};
/* End of enum ProcessOutputFlag Declaration */


/* Start of enum ProcessWaitForFlag Declaration */
#  define PROCESSWAITFORFLAG_IID_STR "23b550c7-78e1-437e-98f0-65fd9757bcd2"
#  define PROCESSWAITFORFLAG_IID { \
    0x23b550c7, 0x78e1, 0x437e, \
    { 0x98, 0xf0, 0x65, 0xfd, 0x97, 0x57, 0xbc, 0xd2 } \
}
enum ProcessWaitForFlag
{
    ProcessWaitForFlag_None = 0,
    ProcessWaitForFlag_Start = 1,
    ProcessWaitForFlag_Terminate = 2,
    ProcessWaitForFlag_StdIn = 4,
    ProcessWaitForFlag_StdOut = 8,
    ProcessWaitForFlag_StdErr = 16
};
/* End of enum ProcessWaitForFlag Declaration */


/* Start of enum ProcessWaitResult Declaration */
#  define PROCESSWAITRESULT_IID_STR "40719cbe-f192-4fe9-a231-6697b3c8e2b4"
#  define PROCESSWAITRESULT_IID { \
    0x40719cbe, 0xf192, 0x4fe9, \
    { 0xa2, 0x31, 0x66, 0x97, 0xb3, 0xc8, 0xe2, 0xb4 } \
}
enum ProcessWaitResult
{
    ProcessWaitResult_None = 0,
    ProcessWaitResult_Start = 1,
    ProcessWaitResult_Terminate = 2,
    ProcessWaitResult_Status = 3,
    ProcessWaitResult_Error = 4,
    ProcessWaitResult_Timeout = 5,
    ProcessWaitResult_StdIn = 6,
    ProcessWaitResult_StdOut = 7,
    ProcessWaitResult_StdErr = 8,
    ProcessWaitResult_WaitFlagNotSupported = 9
};
/* End of enum ProcessWaitResult Declaration */


/* Start of enum CopyFileFlag Declaration */
#  define COPYFILEFLAG_IID_STR "23f79fdf-738a-493d-b80b-42d607c9b916"
#  define COPYFILEFLAG_IID { \
    0x23f79fdf, 0x738a, 0x493d, \
    { 0xb8, 0x0b, 0x42, 0xd6, 0x07, 0xc9, 0xb9, 0x16 } \
}
enum CopyFileFlag
{
    CopyFileFlag_None = 0,
    CopyFileFlag_Recursive = 1,
    CopyFileFlag_Update = 2,
    CopyFileFlag_FollowLinks = 4
};
/* End of enum CopyFileFlag Declaration */


/* Start of enum DirectoryCreateFlag Declaration */
#  define DIRECTORYCREATEFLAG_IID_STR "bd721b0e-ced5-4f79-b368-249897c32a36"
#  define DIRECTORYCREATEFLAG_IID { \
    0xbd721b0e, 0xced5, 0x4f79, \
    { 0xb3, 0x68, 0x24, 0x98, 0x97, 0xc3, 0x2a, 0x36 } \
}
enum DirectoryCreateFlag
{
    DirectoryCreateFlag_None = 0,
    DirectoryCreateFlag_Parents = 1
};
/* End of enum DirectoryCreateFlag Declaration */


/* Start of enum DirectoryRemoveRecFlag Declaration */
#  define DIRECTORYREMOVERECFLAG_IID_STR "455aabf0-7692-48f6-9061-f21579b65769"
#  define DIRECTORYREMOVERECFLAG_IID { \
    0x455aabf0, 0x7692, 0x48f6, \
    { 0x90, 0x61, 0xf2, 0x15, 0x79, 0xb6, 0x57, 0x69 } \
}
enum DirectoryRemoveRecFlag
{
    DirectoryRemoveRecFlag_None = 0,
    DirectoryRemoveRecFlag_ContentAndDir = 1,
    DirectoryRemoveRecFlag_ContentOnly = 2
};
/* End of enum DirectoryRemoveRecFlag Declaration */


/* Start of enum PathRenameFlag Declaration */
#  define PATHRENAMEFLAG_IID_STR "f3baa09f-c758-453d-b91c-c7787d76351d"
#  define PATHRENAMEFLAG_IID { \
    0xf3baa09f, 0xc758, 0x453d, \
    { 0xb9, 0x1c, 0xc7, 0x78, 0x7d, 0x76, 0x35, 0x1d } \
}
enum PathRenameFlag
{
    PathRenameFlag_None = 0,
    PathRenameFlag_NoReplace = 1,
    PathRenameFlag_Replace = 2,
    PathRenameFlag_NoSymlinks = 4
};
/* End of enum PathRenameFlag Declaration */


/* Start of enum ProcessCreateFlag Declaration */
#  define PROCESSCREATEFLAG_IID_STR "35192799-bfde-405d-9bea-c735ab9998e4"
#  define PROCESSCREATEFLAG_IID { \
    0x35192799, 0xbfde, 0x405d, \
    { 0x9b, 0xea, 0xc7, 0x35, 0xab, 0x99, 0x98, 0xe4 } \
}
enum ProcessCreateFlag
{
    ProcessCreateFlag_None = 0,
    ProcessCreateFlag_WaitForProcessStartOnly = 1,
    ProcessCreateFlag_IgnoreOrphanedProcesses = 2,
    ProcessCreateFlag_Hidden = 4,
    ProcessCreateFlag_NoProfile = 8,
    ProcessCreateFlag_WaitForStdOut = 16,
    ProcessCreateFlag_WaitForStdErr = 32,
    ProcessCreateFlag_ExpandArguments = 64
};
/* End of enum ProcessCreateFlag Declaration */


/* Start of enum ProcessPriority Declaration */
#  define PROCESSPRIORITY_IID_STR "ee8cac50-e232-49fe-806b-d1214d9c2e49"
#  define PROCESSPRIORITY_IID { \
    0xee8cac50, 0xe232, 0x49fe, \
    { 0x80, 0x6b, 0xd1, 0x21, 0x4d, 0x9c, 0x2e, 0x49 } \
}
enum ProcessPriority
{
    ProcessPriority_Invalid = 0,
    ProcessPriority_Default = 1
};
/* End of enum ProcessPriority Declaration */


/* Start of enum SymlinkType Declaration */
#  define SYMLINKTYPE_IID_STR "37794668-f8f1-4714-98a5-6f8fa2ed0118"
#  define SYMLINKTYPE_IID { \
    0x37794668, 0xf8f1, 0x4714, \
    { 0x98, 0xa5, 0x6f, 0x8f, 0xa2, 0xed, 0x01, 0x18 } \
}
enum SymlinkType
{
    SymlinkType_Unknown = 0,
    SymlinkType_Directory = 1,
    SymlinkType_File = 2
};
/* End of enum SymlinkType Declaration */


/* Start of enum SymlinkReadFlag Declaration */
#  define SYMLINKREADFLAG_IID_STR "b7fe2b9d-790e-4b25-8adf-1ca33026931f"
#  define SYMLINKREADFLAG_IID { \
    0xb7fe2b9d, 0x790e, 0x4b25, \
    { 0x8a, 0xdf, 0x1c, 0xa3, 0x30, 0x26, 0x93, 0x1f } \
}
enum SymlinkReadFlag
{
    SymlinkReadFlag_None = 0,
    SymlinkReadFlag_NoSymlinks = 1
};
/* End of enum SymlinkReadFlag Declaration */


/* Start of enum ProcessStatus Declaration */
#  define PROCESSSTATUS_IID_STR "4d52368f-5b48-4bfe-b486-acf89139b52f"
#  define PROCESSSTATUS_IID { \
    0x4d52368f, 0x5b48, 0x4bfe, \
    { 0xb4, 0x86, 0xac, 0xf8, 0x91, 0x39, 0xb5, 0x2f } \
}
enum ProcessStatus
{
    ProcessStatus_Undefined = 0,
    ProcessStatus_Starting = 10,
    ProcessStatus_Started = 100,
    ProcessStatus_Paused = 110,
    ProcessStatus_Terminating = 480,
    ProcessStatus_TerminatedNormally = 500,
    ProcessStatus_TerminatedSignal = 510,
    ProcessStatus_TerminatedAbnormally = 511,
    ProcessStatus_TimedOutKilled = 512,
    ProcessStatus_TimedOutAbnormally = 513,
    ProcessStatus_Down = 600,
    ProcessStatus_Error = 800
};
/* End of enum ProcessStatus Declaration */


/* Start of enum ProcessInputStatus Declaration */
#  define PROCESSINPUTSTATUS_IID_STR "a4a0ef9c-29cc-4805-9803-c8215ae9da6c"
#  define PROCESSINPUTSTATUS_IID { \
    0xa4a0ef9c, 0x29cc, 0x4805, \
    { 0x98, 0x03, 0xc8, 0x21, 0x5a, 0xe9, 0xda, 0x6c } \
}
enum ProcessInputStatus
{
    ProcessInputStatus_Undefined = 0,
    ProcessInputStatus_Broken = 1,
    ProcessInputStatus_Available = 10,
    ProcessInputStatus_Written = 50,
    ProcessInputStatus_Overflow = 100
};
/* End of enum ProcessInputStatus Declaration */


/* Start of enum FileStatus Declaration */
#  define FILESTATUS_IID_STR "8c86468b-b97b-4080-8914-e29f5b0abd2c"
#  define FILESTATUS_IID { \
    0x8c86468b, 0xb97b, 0x4080, \
    { 0x89, 0x14, 0xe2, 0x9f, 0x5b, 0x0a, 0xbd, 0x2c } \
}
enum FileStatus
{
    FileStatus_Undefined = 0,
    FileStatus_Opening = 10,
    FileStatus_Open = 100,
    FileStatus_Closing = 150,
    FileStatus_Closed = 200,
    FileStatus_Down = 600,
    FileStatus_Error = 800
};
/* End of enum FileStatus Declaration */


/* Start of enum FsObjType Declaration */
#  define FSOBJTYPE_IID_STR "a1ed437c-b3c3-4ca2-b19c-4239d658d5e8"
#  define FSOBJTYPE_IID { \
    0xa1ed437c, 0xb3c3, 0x4ca2, \
    { 0xb1, 0x9c, 0x42, 0x39, 0xd6, 0x58, 0xd5, 0xe8 } \
}
enum FsObjType
{
    FsObjType_Undefined = 0,
    FsObjType_FIFO = 1,
    FsObjType_DevChar = 10,
    FsObjType_DevBlock = 11,
    FsObjType_Directory = 50,
    FsObjType_File = 80,
    FsObjType_Symlink = 100,
    FsObjType_Socket = 200,
    FsObjType_Whiteout = 400
};
/* End of enum FsObjType Declaration */


/* Start of enum DragAndDropAction Declaration */
#  define DRAGANDDROPACTION_IID_STR "47f3b162-c107-4fcd-bfa7-54b8135c441e"
#  define DRAGANDDROPACTION_IID { \
    0x47f3b162, 0xc107, 0x4fcd, \
    { 0xbf, 0xa7, 0x54, 0xb8, 0x13, 0x5c, 0x44, 0x1e } \
}
enum DragAndDropAction
{
    DragAndDropAction_Ignore = 0,
    DragAndDropAction_Copy = 1,
    DragAndDropAction_Move = 2,
    DragAndDropAction_Link = 3
};
/* End of enum DragAndDropAction Declaration */


/* Start of enum DirectoryOpenFlag Declaration */
#  define DIRECTORYOPENFLAG_IID_STR "5138837a-8fd2-4194-a1b0-08f7bc3949d0"
#  define DIRECTORYOPENFLAG_IID { \
    0x5138837a, 0x8fd2, 0x4194, \
    { 0xa1, 0xb0, 0x08, 0xf7, 0xbc, 0x39, 0x49, 0xd0 } \
}
enum DirectoryOpenFlag
{
    DirectoryOpenFlag_None = 0,
    DirectoryOpenFlag_NoSymlinks = 1
};
/* End of enum DirectoryOpenFlag Declaration */


/* Start of enum MediumState Declaration */
#  define MEDIUMSTATE_IID_STR "ef41e980-e012-43cd-9dea-479d4ef14d13"
#  define MEDIUMSTATE_IID { \
    0xef41e980, 0xe012, 0x43cd, \
    { 0x9d, 0xea, 0x47, 0x9d, 0x4e, 0xf1, 0x4d, 0x13 } \
}
enum MediumState
{
    MediumState_NotCreated = 0,
    MediumState_Created = 1,
    MediumState_LockedRead = 2,
    MediumState_LockedWrite = 3,
    MediumState_Inaccessible = 4,
    MediumState_Creating = 5,
    MediumState_Deleting = 6
};
/* End of enum MediumState Declaration */


/* Start of enum MediumType Declaration */
#  define MEDIUMTYPE_IID_STR "fe663fb5-c244-4e1b-9d81-c628b417dd04"
#  define MEDIUMTYPE_IID { \
    0xfe663fb5, 0xc244, 0x4e1b, \
    { 0x9d, 0x81, 0xc6, 0x28, 0xb4, 0x17, 0xdd, 0x04 } \
}
enum MediumType
{
    MediumType_Normal = 0,
    MediumType_Immutable = 1,
    MediumType_Writethrough = 2,
    MediumType_Shareable = 3,
    MediumType_Readonly = 4,
    MediumType_MultiAttach = 5
};
/* End of enum MediumType Declaration */


/* Start of enum MediumVariant Declaration */
#  define MEDIUMVARIANT_IID_STR "80685b6b-e42f-497d-8271-e77bf3c61ada"
#  define MEDIUMVARIANT_IID { \
    0x80685b6b, 0xe42f, 0x497d, \
    { 0x82, 0x71, 0xe7, 0x7b, 0xf3, 0xc6, 0x1a, 0xda } \
}
enum MediumVariant
{
    MediumVariant_Standard = 0,
    MediumVariant_VmdkSplit2G = 0x01,
    MediumVariant_VmdkRawDisk = 0x02,
    MediumVariant_VmdkStreamOptimized = 0x04,
    MediumVariant_VmdkESX = 0x08,
    MediumVariant_Fixed = 0x10000,
    MediumVariant_Diff = 0x20000,
    MediumVariant_NoCreateDir = 0x40000000
};
/* End of enum MediumVariant Declaration */


/* Start of enum DataType Declaration */
#  define DATATYPE_IID_STR "d90ea51e-a3f1-4a01-beb1-c1723c0d3ba7"
#  define DATATYPE_IID { \
    0xd90ea51e, 0xa3f1, 0x4a01, \
    { 0xbe, 0xb1, 0xc1, 0x72, 0x3c, 0x0d, 0x3b, 0xa7 } \
}
enum DataType
{
    DataType_Int32 = 0,
    DataType_Int8 = 1,
    DataType_String = 2
};
/* End of enum DataType Declaration */


/* Start of enum DataFlags Declaration */
#  define DATAFLAGS_IID_STR "86884dcf-1d6b-4f1b-b4bf-f5aa44959d60"
#  define DATAFLAGS_IID { \
    0x86884dcf, 0x1d6b, 0x4f1b, \
    { 0xb4, 0xbf, 0xf5, 0xaa, 0x44, 0x95, 0x9d, 0x60 } \
}
enum DataFlags
{
    DataFlags_None = 0x00,
    DataFlags_Mandatory = 0x01,
    DataFlags_Expert = 0x02,
    DataFlags_Array = 0x04,
    DataFlags_FlagMask = 0x07
};
/* End of enum DataFlags Declaration */


/* Start of enum MediumFormatCapabilities Declaration */
#  define MEDIUMFORMATCAPABILITIES_IID_STR "7342ba79-7ce0-4d94-8f86-5ed5a185d9bd"
#  define MEDIUMFORMATCAPABILITIES_IID { \
    0x7342ba79, 0x7ce0, 0x4d94, \
    { 0x8f, 0x86, 0x5e, 0xd5, 0xa1, 0x85, 0xd9, 0xbd } \
}
enum MediumFormatCapabilities
{
    MediumFormatCapabilities_Uuid = 0x01,
    MediumFormatCapabilities_CreateFixed = 0x02,
    MediumFormatCapabilities_CreateDynamic = 0x04,
    MediumFormatCapabilities_CreateSplit2G = 0x08,
    MediumFormatCapabilities_Differencing = 0x10,
    MediumFormatCapabilities_Asynchronous = 0x20,
    MediumFormatCapabilities_File = 0x40,
    MediumFormatCapabilities_Properties = 0x80,
    MediumFormatCapabilities_TcpNetworking = 0x100,
    MediumFormatCapabilities_VFS = 0x200,
    MediumFormatCapabilities_CapabilityMask = 0x3FF
};
/* End of enum MediumFormatCapabilities Declaration */


/* Start of enum MouseButtonState Declaration */
#  define MOUSEBUTTONSTATE_IID_STR "9ee094b8-b28a-4d56-a166-973cb588d7f8"
#  define MOUSEBUTTONSTATE_IID { \
    0x9ee094b8, 0xb28a, 0x4d56, \
    { 0xa1, 0x66, 0x97, 0x3c, 0xb5, 0x88, 0xd7, 0xf8 } \
}
enum MouseButtonState
{
    MouseButtonState_LeftButton = 0x01,
    MouseButtonState_RightButton = 0x02,
    MouseButtonState_MiddleButton = 0x04,
    MouseButtonState_WheelUp = 0x08,
    MouseButtonState_WheelDown = 0x10,
    MouseButtonState_XButton1 = 0x20,
    MouseButtonState_XButton2 = 0x40,
    MouseButtonState_MouseStateMask = 0x7F
};
/* End of enum MouseButtonState Declaration */


/* Start of enum TouchContactState Declaration */
#  define TOUCHCONTACTSTATE_IID_STR "3f942686-2506-421c-927c-90d4b45f4a38"
#  define TOUCHCONTACTSTATE_IID { \
    0x3f942686, 0x2506, 0x421c, \
    { 0x92, 0x7c, 0x90, 0xd4, 0xb4, 0x5f, 0x4a, 0x38 } \
}
enum TouchContactState
{
    TouchContactState_None = 0x00,
    TouchContactState_InContact = 0x01,
    TouchContactState_InRange = 0x02,
    TouchContactState_ContactStateMask = 0x03
};
/* End of enum TouchContactState Declaration */


/* Start of enum FramebufferPixelFormat Declaration */
#  define FRAMEBUFFERPIXELFORMAT_IID_STR "7acfd5ed-29e3-45e3-8136-73c9224f3d2d"
#  define FRAMEBUFFERPIXELFORMAT_IID { \
    0x7acfd5ed, 0x29e3, 0x45e3, \
    { 0x81, 0x36, 0x73, 0xc9, 0x22, 0x4f, 0x3d, 0x2d } \
}
enum FramebufferPixelFormat
{
    FramebufferPixelFormat_Opaque = 0,
    FramebufferPixelFormat_FOURCC_RGB = 0x32424752
};
/* End of enum FramebufferPixelFormat Declaration */


/* Start of enum NetworkAttachmentType Declaration */
#  define NETWORKATTACHMENTTYPE_IID_STR "524a8f9d-4b86-4b51-877d-1aa27c4ebeac"
#  define NETWORKATTACHMENTTYPE_IID { \
    0x524a8f9d, 0x4b86, 0x4b51, \
    { 0x87, 0x7d, 0x1a, 0xa2, 0x7c, 0x4e, 0xbe, 0xac } \
}
enum NetworkAttachmentType
{
    NetworkAttachmentType_Null = 0,
    NetworkAttachmentType_NAT = 1,
    NetworkAttachmentType_Bridged = 2,
    NetworkAttachmentType_Internal = 3,
    NetworkAttachmentType_HostOnly = 4,
    NetworkAttachmentType_Generic = 5,
    NetworkAttachmentType_NATNetwork = 6
};
/* End of enum NetworkAttachmentType Declaration */


/* Start of enum NetworkAdapterType Declaration */
#  define NETWORKADAPTERTYPE_IID_STR "3c2281e4-d952-4e87-8c7d-24379cb6a81c"
#  define NETWORKADAPTERTYPE_IID { \
    0x3c2281e4, 0xd952, 0x4e87, \
    { 0x8c, 0x7d, 0x24, 0x37, 0x9c, 0xb6, 0xa8, 0x1c } \
}
enum NetworkAdapterType
{
    NetworkAdapterType_Null = 0,
    NetworkAdapterType_Am79C970A = 1,
    NetworkAdapterType_Am79C973 = 2,
    NetworkAdapterType_I82540EM = 3,
    NetworkAdapterType_I82543GC = 4,
    NetworkAdapterType_I82545EM = 5,
    NetworkAdapterType_Virtio = 6
};
/* End of enum NetworkAdapterType Declaration */


/* Start of enum NetworkAdapterPromiscModePolicy Declaration */
#  define NETWORKADAPTERPROMISCMODEPOLICY_IID_STR "c963768a-376f-4c85-8d84-d8ced4b7269e"
#  define NETWORKADAPTERPROMISCMODEPOLICY_IID { \
    0xc963768a, 0x376f, 0x4c85, \
    { 0x8d, 0x84, 0xd8, 0xce, 0xd4, 0xb7, 0x26, 0x9e } \
}
enum NetworkAdapterPromiscModePolicy
{
    NetworkAdapterPromiscModePolicy_Deny = 1,
    NetworkAdapterPromiscModePolicy_AllowNetwork = 2,
    NetworkAdapterPromiscModePolicy_AllowAll = 3
};
/* End of enum NetworkAdapterPromiscModePolicy Declaration */


/* Start of enum PortMode Declaration */
#  define PORTMODE_IID_STR "533b5fe3-0185-4197-86a7-17e37dd39d76"
#  define PORTMODE_IID { \
    0x533b5fe3, 0x0185, 0x4197, \
    { 0x86, 0xa7, 0x17, 0xe3, 0x7d, 0xd3, 0x9d, 0x76 } \
}
enum PortMode
{
    PortMode_Disconnected = 0,
    PortMode_HostPipe = 1,
    PortMode_HostDevice = 2,
    PortMode_RawFile = 3
};
/* End of enum PortMode Declaration */


/* Start of enum USBControllerType Declaration */
#  define USBCONTROLLERTYPE_IID_STR "8fdd1c6a-5412-41da-ab07-7baed7d6e18e"
#  define USBCONTROLLERTYPE_IID { \
    0x8fdd1c6a, 0x5412, 0x41da, \
    { 0xab, 0x07, 0x7b, 0xae, 0xd7, 0xd6, 0xe1, 0x8e } \
}
enum USBControllerType
{
    USBControllerType_Null = 0,
    USBControllerType_OHCI = 1,
    USBControllerType_EHCI = 2,
    USBControllerType_Last = 3
};
/* End of enum USBControllerType Declaration */


/* Start of enum USBDeviceState Declaration */
#  define USBDEVICESTATE_IID_STR "b99a2e65-67fb-4882-82fd-f3e5e8193ab4"
#  define USBDEVICESTATE_IID { \
    0xb99a2e65, 0x67fb, 0x4882, \
    { 0x82, 0xfd, 0xf3, 0xe5, 0xe8, 0x19, 0x3a, 0xb4 } \
}
enum USBDeviceState
{
    USBDeviceState_NotSupported = 0,
    USBDeviceState_Unavailable = 1,
    USBDeviceState_Busy = 2,
    USBDeviceState_Available = 3,
    USBDeviceState_Held = 4,
    USBDeviceState_Captured = 5
};
/* End of enum USBDeviceState Declaration */


/* Start of enum USBDeviceFilterAction Declaration */
#  define USBDEVICEFILTERACTION_IID_STR "cbc30a49-2f4e-43b5-9da6-121320475933"
#  define USBDEVICEFILTERACTION_IID { \
    0xcbc30a49, 0x2f4e, 0x43b5, \
    { 0x9d, 0xa6, 0x12, 0x13, 0x20, 0x47, 0x59, 0x33 } \
}
enum USBDeviceFilterAction
{
    USBDeviceFilterAction_Null = 0,
    USBDeviceFilterAction_Ignore = 1,
    USBDeviceFilterAction_Hold = 2
};
/* End of enum USBDeviceFilterAction Declaration */


/* Start of enum AudioDriverType Declaration */
#  define AUDIODRIVERTYPE_IID_STR "4bcc3d73-c2fe-40db-b72f-0c2ca9d68496"
#  define AUDIODRIVERTYPE_IID { \
    0x4bcc3d73, 0xc2fe, 0x40db, \
    { 0xb7, 0x2f, 0x0c, 0x2c, 0xa9, 0xd6, 0x84, 0x96 } \
}
enum AudioDriverType
{
    AudioDriverType_Null = 0,
    AudioDriverType_WinMM = 1,
    AudioDriverType_OSS = 2,
    AudioDriverType_ALSA = 3,
    AudioDriverType_DirectSound = 4,
    AudioDriverType_CoreAudio = 5,
    AudioDriverType_MMPM = 6,
    AudioDriverType_Pulse = 7,
    AudioDriverType_SolAudio = 8
};
/* End of enum AudioDriverType Declaration */


/* Start of enum AudioControllerType Declaration */
#  define AUDIOCONTROLLERTYPE_IID_STR "7afd395c-42c3-444e-8788-3ce80292f36c"
#  define AUDIOCONTROLLERTYPE_IID { \
    0x7afd395c, 0x42c3, 0x444e, \
    { 0x87, 0x88, 0x3c, 0xe8, 0x02, 0x92, 0xf3, 0x6c } \
}
enum AudioControllerType
{
    AudioControllerType_AC97 = 0,
    AudioControllerType_SB16 = 1,
    AudioControllerType_HDA = 2
};
/* End of enum AudioControllerType Declaration */


/* Start of enum AuthType Declaration */
#  define AUTHTYPE_IID_STR "7eef6ef6-98c2-4dc2-ab35-10d2b292028d"
#  define AUTHTYPE_IID { \
    0x7eef6ef6, 0x98c2, 0x4dc2, \
    { 0xab, 0x35, 0x10, 0xd2, 0xb2, 0x92, 0x02, 0x8d } \
}
enum AuthType
{
    AuthType_Null = 0,
    AuthType_External = 1,
    AuthType_Guest = 2
};
/* End of enum AuthType Declaration */


/* Start of enum Reason Declaration */
#  define REASON_IID_STR "e7e8e097-299d-4e98-8bbc-c31c2d47d0cc"
#  define REASON_IID { \
    0xe7e8e097, 0x299d, 0x4e98, \
    { 0x8b, 0xbc, 0xc3, 0x1c, 0x2d, 0x47, 0xd0, 0xcc } \
}
enum Reason
{
    Reason_Unspecified = 0,
    Reason_HostSuspend = 1,
    Reason_HostResume = 2,
    Reason_HostBatteryLow = 3
};
/* End of enum Reason Declaration */


/* Start of enum StorageBus Declaration */
#  define STORAGEBUS_IID_STR "eee67ab3-668d-4ef5-91e0-7025fe4a0d7a"
#  define STORAGEBUS_IID { \
    0xeee67ab3, 0x668d, 0x4ef5, \
    { 0x91, 0xe0, 0x70, 0x25, 0xfe, 0x4a, 0x0d, 0x7a } \
}
enum StorageBus
{
    StorageBus_Null = 0,
    StorageBus_IDE = 1,
    StorageBus_SATA = 2,
    StorageBus_SCSI = 3,
    StorageBus_Floppy = 4,
    StorageBus_SAS = 5
};
/* End of enum StorageBus Declaration */


/* Start of enum StorageControllerType Declaration */
#  define STORAGECONTROLLERTYPE_IID_STR "8a412b8a-f43e-4456-bd37-b474f0879a58"
#  define STORAGECONTROLLERTYPE_IID { \
    0x8a412b8a, 0xf43e, 0x4456, \
    { 0xbd, 0x37, 0xb4, 0x74, 0xf0, 0x87, 0x9a, 0x58 } \
}
enum StorageControllerType
{
    StorageControllerType_Null = 0,
    StorageControllerType_LsiLogic = 1,
    StorageControllerType_BusLogic = 2,
    StorageControllerType_IntelAhci = 3,
    StorageControllerType_PIIX3 = 4,
    StorageControllerType_PIIX4 = 5,
    StorageControllerType_ICH6 = 6,
    StorageControllerType_I82078 = 7,
    StorageControllerType_LsiLogicSas = 8
};
/* End of enum StorageControllerType Declaration */


/* Start of enum ChipsetType Declaration */
#  define CHIPSETTYPE_IID_STR "8b4096a8-a7c3-4d3b-bbb1-05a0a51ec394"
#  define CHIPSETTYPE_IID { \
    0x8b4096a8, 0xa7c3, 0x4d3b, \
    { 0xbb, 0xb1, 0x05, 0xa0, 0xa5, 0x1e, 0xc3, 0x94 } \
}
enum ChipsetType
{
    ChipsetType_Null = 0,
    ChipsetType_PIIX3 = 1,
    ChipsetType_ICH9 = 2
};
/* End of enum ChipsetType Declaration */


/* Start of enum NATAliasMode Declaration */
#  define NATALIASMODE_IID_STR "67772168-50d9-11df-9669-7fb714ee4fa1"
#  define NATALIASMODE_IID { \
    0x67772168, 0x50d9, 0x11df, \
    { 0x96, 0x69, 0x7f, 0xb7, 0x14, 0xee, 0x4f, 0xa1 } \
}
enum NATAliasMode
{
    NATAliasMode_AliasLog = 0x1,
    NATAliasMode_AliasProxyOnly = 0x02,
    NATAliasMode_AliasUseSamePorts = 0x04
};
/* End of enum NATAliasMode Declaration */


/* Start of enum NATProtocol Declaration */
#  define NATPROTOCOL_IID_STR "e90164be-eb03-11de-94af-fff9b1c1b19f"
#  define NATPROTOCOL_IID { \
    0xe90164be, 0xeb03, 0x11de, \
    { 0x94, 0xaf, 0xff, 0xf9, 0xb1, 0xc1, 0xb1, 0x9f } \
}
enum NATProtocol
{
    NATProtocol_UDP = 0,
    NATProtocol_TCP = 1
};
/* End of enum NATProtocol Declaration */


/* Start of enum BandwidthGroupType Declaration */
#  define BANDWIDTHGROUPTYPE_IID_STR "1d92b67d-dc69-4be9-ad4c-93a01e1e0c8e"
#  define BANDWIDTHGROUPTYPE_IID { \
    0x1d92b67d, 0xdc69, 0x4be9, \
    { 0xad, 0x4c, 0x93, 0xa0, 0x1e, 0x1e, 0x0c, 0x8e } \
}
enum BandwidthGroupType
{
    BandwidthGroupType_Null = 0,
    BandwidthGroupType_Disk = 1,
    BandwidthGroupType_Network = 2
};
/* End of enum BandwidthGroupType Declaration */


/* Start of enum VBoxEventType Declaration */
#  define VBOXEVENTTYPE_IID_STR "5248e377-e578-47d7-b07b-84b1db6db8a8"
#  define VBOXEVENTTYPE_IID { \
    0x5248e377, 0xe578, 0x47d7, \
    { 0xb0, 0x7b, 0x84, 0xb1, 0xdb, 0x6d, 0xb8, 0xa8 } \
}
enum VBoxEventType
{
    VBoxEventType_Invalid = 0,
    VBoxEventType_Any = 1,
    VBoxEventType_Vetoable = 2,
    VBoxEventType_MachineEvent = 3,
    VBoxEventType_SnapshotEvent = 4,
    VBoxEventType_InputEvent = 5,
    VBoxEventType_LastWildcard = 31,
    VBoxEventType_OnMachineStateChanged = 32,
    VBoxEventType_OnMachineDataChanged = 33,
    VBoxEventType_OnExtraDataChanged = 34,
    VBoxEventType_OnExtraDataCanChange = 35,
    VBoxEventType_OnMediumRegistered = 36,
    VBoxEventType_OnMachineRegistered = 37,
    VBoxEventType_OnSessionStateChanged = 38,
    VBoxEventType_OnSnapshotTaken = 39,
    VBoxEventType_OnSnapshotDeleted = 40,
    VBoxEventType_OnSnapshotChanged = 41,
    VBoxEventType_OnGuestPropertyChanged = 42,
    VBoxEventType_OnMousePointerShapeChanged = 43,
    VBoxEventType_OnMouseCapabilityChanged = 44,
    VBoxEventType_OnKeyboardLedsChanged = 45,
    VBoxEventType_OnStateChanged = 46,
    VBoxEventType_OnAdditionsStateChanged = 47,
    VBoxEventType_OnNetworkAdapterChanged = 48,
    VBoxEventType_OnSerialPortChanged = 49,
    VBoxEventType_OnParallelPortChanged = 50,
    VBoxEventType_OnStorageControllerChanged = 51,
    VBoxEventType_OnMediumChanged = 52,
    VBoxEventType_OnVRDEServerChanged = 53,
    VBoxEventType_OnUSBControllerChanged = 54,
    VBoxEventType_OnUSBDeviceStateChanged = 55,
    VBoxEventType_OnSharedFolderChanged = 56,
    VBoxEventType_OnRuntimeError = 57,
    VBoxEventType_OnCanShowWindow = 58,
    VBoxEventType_OnShowWindow = 59,
    VBoxEventType_OnCPUChanged = 60,
    VBoxEventType_OnVRDEServerInfoChanged = 61,
    VBoxEventType_OnEventSourceChanged = 62,
    VBoxEventType_OnCPUExecutionCapChanged = 63,
    VBoxEventType_OnGuestKeyboard = 64,
    VBoxEventType_OnGuestMouse = 65,
    VBoxEventType_OnNATRedirect = 66,
    VBoxEventType_OnHostPCIDevicePlug = 67,
    VBoxEventType_OnVBoxSVCAvailabilityChanged = 68,
    VBoxEventType_OnBandwidthGroupChanged = 69,
    VBoxEventType_OnGuestMonitorChanged = 70,
    VBoxEventType_OnStorageDeviceChanged = 71,
    VBoxEventType_OnClipboardModeChanged = 72,
    VBoxEventType_OnDragAndDropModeChanged = 73,
    VBoxEventType_OnNATNetworkChanged = 74,
    VBoxEventType_OnNATNetworkStartStop = 75,
    VBoxEventType_OnNATNetworkAlter = 76,
    VBoxEventType_OnNATNetworkCreationDeletion = 77,
    VBoxEventType_OnNATNetworkSetting = 78,
    VBoxEventType_OnNATNetworkPortForward = 79,
    VBoxEventType_OnGuestSessionStateChanged = 80,
    VBoxEventType_OnGuestSessionRegistered = 81,
    VBoxEventType_OnGuestProcessRegistered = 82,
    VBoxEventType_OnGuestProcessStateChanged = 83,
    VBoxEventType_OnGuestProcessInputNotify = 84,
    VBoxEventType_OnGuestProcessOutput = 85,
    VBoxEventType_OnGuestFileRegistered = 86,
    VBoxEventType_OnGuestFileStateChanged = 87,
    VBoxEventType_OnGuestFileOffsetChanged = 88,
    VBoxEventType_OnGuestFileRead = 89,
    VBoxEventType_OnGuestFileWrite = 90,
    VBoxEventType_OnVideoCaptureChanged = 91,
    VBoxEventType_OnGuestUserStateChanged = 92,
    VBoxEventType_OnGuestMultiTouch = 93,
    VBoxEventType_OnHostNameResolutionConfigurationChange = 94,
    VBoxEventType_Last = 95
};
/* End of enum VBoxEventType Declaration */


/* Start of enum GuestMouseEventMode Declaration */
#  define GUESTMOUSEEVENTMODE_IID_STR "4b500146-ebba-4b7c-bc29-69c2d57a5caf"
#  define GUESTMOUSEEVENTMODE_IID { \
    0x4b500146, 0xebba, 0x4b7c, \
    { 0xbc, 0x29, 0x69, 0xc2, 0xd5, 0x7a, 0x5c, 0xaf } \
}
enum GuestMouseEventMode
{
    GuestMouseEventMode_Relative = 0,
    GuestMouseEventMode_Absolute = 1
};
/* End of enum GuestMouseEventMode Declaration */


/* Start of enum GuestMonitorChangedEventType Declaration */
#  define GUESTMONITORCHANGEDEVENTTYPE_IID_STR "ef172985-7e36-4297-95be-e46396968d66"
#  define GUESTMONITORCHANGEDEVENTTYPE_IID { \
    0xef172985, 0x7e36, 0x4297, \
    { 0x95, 0xbe, 0xe4, 0x63, 0x96, 0x96, 0x8d, 0x66 } \
}
enum GuestMonitorChangedEventType
{
    GuestMonitorChangedEventType_Enabled = 0,
    GuestMonitorChangedEventType_Disabled = 1,
    GuestMonitorChangedEventType_NewOrigin = 2
};
/* End of enum GuestMonitorChangedEventType Declaration */


/* Start of struct IVirtualBoxErrorInfo Declaration */
#  define IVIRTUALBOXERRORINFO_IID_STR "c1bcc6d5-7966-481d-ab0b-d0ed73e28135"
#  define IVIRTUALBOXERRORINFO_IID { \
    0xc1bcc6d5, 0x7966, 0x481d, \
    { 0xab, 0x0b, 0xd0, 0xed, 0x73, 0xe2, 0x81, 0x35 } \
}
struct IVirtualBoxErrorInfo_vtbl
{
    struct nsIException_vtbl nsiexception;

    nsresult (*GetResultCode)(IVirtualBoxErrorInfo *pThis, PRInt32 *resultCode);

    nsresult (*GetResultDetail)(IVirtualBoxErrorInfo *pThis, PRInt32 *resultDetail);

    nsresult (*GetInterfaceID)(IVirtualBoxErrorInfo *pThis, PRUnichar * *interfaceID);

    nsresult (*GetComponent)(IVirtualBoxErrorInfo *pThis, PRUnichar * *component);

    nsresult (*GetText)(IVirtualBoxErrorInfo *pThis, PRUnichar * *text);

    nsresult (*GetNext)(IVirtualBoxErrorInfo *pThis, IVirtualBoxErrorInfo * *next);

};

struct IVirtualBoxErrorInfo
{
    struct IVirtualBoxErrorInfo_vtbl *vtbl;
};
/* End of struct IVirtualBoxErrorInfo Declaration */


/* Start of struct INATNetwork Declaration */
#  define INATNETWORK_IID_STR "a63c75da-4c99-4e9d-8351-eb73651c18cc"
#  define INATNETWORK_IID { \
    0xa63c75da, 0x4c99, 0x4e9d, \
    { 0x83, 0x51, 0xeb, 0x73, 0x65, 0x1c, 0x18, 0xcc } \
}
struct INATNetwork_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetNetworkName)(INATNetwork *pThis, PRUnichar * *networkName);
    nsresult (*SetNetworkName)(INATNetwork *pThis, PRUnichar * networkName);

    nsresult (*GetEnabled)(INATNetwork *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(INATNetwork *pThis, PRBool enabled);

    nsresult (*GetNetwork)(INATNetwork *pThis, PRUnichar * *network);
    nsresult (*SetNetwork)(INATNetwork *pThis, PRUnichar * network);

    nsresult (*GetGateway)(INATNetwork *pThis, PRUnichar * *gateway);

    nsresult (*GetIPv6Enabled)(INATNetwork *pThis, PRBool *IPv6Enabled);
    nsresult (*SetIPv6Enabled)(INATNetwork *pThis, PRBool IPv6Enabled);

    nsresult (*GetIPv6Prefix)(INATNetwork *pThis, PRUnichar * *IPv6Prefix);
    nsresult (*SetIPv6Prefix)(INATNetwork *pThis, PRUnichar * IPv6Prefix);

    nsresult (*GetAdvertiseDefaultIPv6RouteEnabled)(INATNetwork *pThis, PRBool *advertiseDefaultIPv6RouteEnabled);
    nsresult (*SetAdvertiseDefaultIPv6RouteEnabled)(INATNetwork *pThis, PRBool advertiseDefaultIPv6RouteEnabled);

    nsresult (*GetNeedDhcpServer)(INATNetwork *pThis, PRBool *needDhcpServer);
    nsresult (*SetNeedDhcpServer)(INATNetwork *pThis, PRBool needDhcpServer);

    nsresult (*GetEventSource)(INATNetwork *pThis, IEventSource * *eventSource);

    nsresult (*GetPortForwardRules4)(INATNetwork *pThis, PRUint32 *portForwardRules4Size, PRUnichar * **portForwardRules4);

    nsresult (*GetLocalMappings)(INATNetwork *pThis, PRUint32 *localMappingsSize, PRUnichar * **localMappings);

    nsresult (*GetLoopbackIp6)(INATNetwork *pThis, PRInt32 *loopbackIp6);
    nsresult (*SetLoopbackIp6)(INATNetwork *pThis, PRInt32 loopbackIp6);

    nsresult (*GetPortForwardRules6)(INATNetwork *pThis, PRUint32 *portForwardRules6Size, PRUnichar * **portForwardRules6);

    nsresult (*AddLocalMapping)(
        INATNetwork *pThis,
        PRUnichar * hostid,
        PRInt32 offset
    );

    nsresult (*AddPortForwardRule)(
        INATNetwork *pThis,
        PRBool isIpv6,
        PRUnichar * ruleName,
        PRUint32 proto,
        PRUnichar * hostIP,
        PRUint16 hostPort,
        PRUnichar * guestIP,
        PRUint16 guestPort
    );

    nsresult (*RemovePortForwardRule)(
        INATNetwork *pThis,
        PRBool iSipv6,
        PRUnichar * ruleName
    );

    nsresult (*Start)(
        INATNetwork *pThis,
        PRUnichar * trunkType
    );

    nsresult (*Stop)(INATNetwork *pThis );

};

struct INATNetwork
{
    struct INATNetwork_vtbl *vtbl;
};
/* End of struct INATNetwork Declaration */


/* Start of struct IDHCPServer Declaration */
#  define IDHCPSERVER_IID_STR "ff0774c5-1f62-4bc3-919c-7fc942bf1d25"
#  define IDHCPSERVER_IID { \
    0xff0774c5, 0x1f62, 0x4bc3, \
    { 0x91, 0x9c, 0x7f, 0xc9, 0x42, 0xbf, 0x1d, 0x25 } \
}
struct IDHCPServer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetEventSource)(IDHCPServer *pThis, IEventSource * *eventSource);

    nsresult (*GetEnabled)(IDHCPServer *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(IDHCPServer *pThis, PRBool enabled);

    nsresult (*GetIPAddress)(IDHCPServer *pThis, PRUnichar * *IPAddress);

    nsresult (*GetNetworkMask)(IDHCPServer *pThis, PRUnichar * *networkMask);

    nsresult (*GetNetworkName)(IDHCPServer *pThis, PRUnichar * *networkName);

    nsresult (*GetLowerIP)(IDHCPServer *pThis, PRUnichar * *lowerIP);

    nsresult (*GetUpperIP)(IDHCPServer *pThis, PRUnichar * *upperIP);

    nsresult (*GetGlobalOptions)(IDHCPServer *pThis, PRUint32 *globalOptionsSize, PRUnichar * **globalOptions);

    nsresult (*GetVmConfigs)(IDHCPServer *pThis, PRUint32 *vmConfigsSize, PRUnichar * **vmConfigs);

    nsresult (*AddGlobalOption)(
        IDHCPServer *pThis,
        PRUint32 option,
        PRUnichar * value
    );

    nsresult (*AddVmSlotOption)(
        IDHCPServer *pThis,
        PRUnichar * vmname,
        PRInt32 slot,
        PRUint32 option,
        PRUnichar * value
    );

    nsresult (*RemoveVmSlotOptions)(
        IDHCPServer *pThis,
        PRUnichar * vmname,
        PRInt32 slot
    );

    nsresult (*GetVmSlotOptions)(
        IDHCPServer *pThis,
        PRUnichar * vmname,
        PRInt32 slot,
        PRUint32 *optionSize,
        PRUnichar *** option
    );

    nsresult (*GetMacOptions)(
        IDHCPServer *pThis,
        PRUnichar * mac,
        PRUint32 *optionSize,
        PRUnichar *** option
    );

    nsresult (*SetConfiguration)(
        IDHCPServer *pThis,
        PRUnichar * IPAddress,
        PRUnichar * networkMask,
        PRUnichar * FromIPAddress,
        PRUnichar * ToIPAddress
    );

    nsresult (*Start)(
        IDHCPServer *pThis,
        PRUnichar * networkName,
        PRUnichar * trunkName,
        PRUnichar * trunkType
    );

    nsresult (*Stop)(IDHCPServer *pThis );

};

struct IDHCPServer
{
    struct IDHCPServer_vtbl *vtbl;
};
/* End of struct IDHCPServer Declaration */


/* Start of struct IVirtualBox Declaration */
#  define IVIRTUALBOX_IID_STR "fafa4e17-1ee2-4905-a10e-fe7c18bf5554"
#  define IVIRTUALBOX_IID { \
    0xfafa4e17, 0x1ee2, 0x4905, \
    { 0xa1, 0x0e, 0xfe, 0x7c, 0x18, 0xbf, 0x55, 0x54 } \
}
struct IVirtualBox_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetVersion)(IVirtualBox *pThis, PRUnichar * *version);

    nsresult (*GetVersionNormalized)(IVirtualBox *pThis, PRUnichar * *versionNormalized);

    nsresult (*GetRevision)(IVirtualBox *pThis, PRUint32 *revision);

    nsresult (*GetPackageType)(IVirtualBox *pThis, PRUnichar * *packageType);

    nsresult (*GetAPIVersion)(IVirtualBox *pThis, PRUnichar * *APIVersion);

    nsresult (*GetHomeFolder)(IVirtualBox *pThis, PRUnichar * *homeFolder);

    nsresult (*GetSettingsFilePath)(IVirtualBox *pThis, PRUnichar * *settingsFilePath);

    nsresult (*GetHost)(IVirtualBox *pThis, IHost * *host);

    nsresult (*GetSystemProperties)(IVirtualBox *pThis, ISystemProperties * *systemProperties);

    nsresult (*GetMachines)(IVirtualBox *pThis, PRUint32 *machinesSize, IMachine * **machines);

    nsresult (*GetMachineGroups)(IVirtualBox *pThis, PRUint32 *machineGroupsSize, PRUnichar * **machineGroups);

    nsresult (*GetHardDisks)(IVirtualBox *pThis, PRUint32 *hardDisksSize, IMedium * **hardDisks);

    nsresult (*GetDVDImages)(IVirtualBox *pThis, PRUint32 *DVDImagesSize, IMedium * **DVDImages);

    nsresult (*GetFloppyImages)(IVirtualBox *pThis, PRUint32 *floppyImagesSize, IMedium * **floppyImages);

    nsresult (*GetProgressOperations)(IVirtualBox *pThis, PRUint32 *progressOperationsSize, IProgress * **progressOperations);

    nsresult (*GetGuestOSTypes)(IVirtualBox *pThis, PRUint32 *guestOSTypesSize, IGuestOSType * **guestOSTypes);

    nsresult (*GetSharedFolders)(IVirtualBox *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult (*GetPerformanceCollector)(IVirtualBox *pThis, IPerformanceCollector * *performanceCollector);

    nsresult (*GetDHCPServers)(IVirtualBox *pThis, PRUint32 *DHCPServersSize, IDHCPServer * **DHCPServers);

    nsresult (*GetNATNetworks)(IVirtualBox *pThis, PRUint32 *NATNetworksSize, INATNetwork * **NATNetworks);

    nsresult (*GetEventSource)(IVirtualBox *pThis, IEventSource * *eventSource);

    nsresult (*GetExtensionPackManager)(IVirtualBox *pThis, IExtPackManager * *extensionPackManager);

    nsresult (*GetInternalNetworks)(IVirtualBox *pThis, PRUint32 *internalNetworksSize, PRUnichar * **internalNetworks);

    nsresult (*GetGenericNetworkDrivers)(IVirtualBox *pThis, PRUint32 *genericNetworkDriversSize, PRUnichar * **genericNetworkDrivers);

    nsresult (*ComposeMachineFilename)(
        IVirtualBox *pThis,
        PRUnichar * name,
        PRUnichar * group,
        PRUnichar * createFlags,
        PRUnichar * baseFolder,
        PRUnichar * * file
    );

    nsresult (*CreateMachine)(
        IVirtualBox *pThis,
        PRUnichar * settingsFile,
        PRUnichar * name,
        PRUint32 groupsSize,
        PRUnichar ** groups,
        PRUnichar * osTypeId,
        PRUnichar * flags,
        IMachine * * machine
    );

    nsresult (*OpenMachine)(
        IVirtualBox *pThis,
        PRUnichar * settingsFile,
        IMachine * * machine
    );

    nsresult (*RegisterMachine)(
        IVirtualBox *pThis,
        IMachine * machine
    );

    nsresult (*FindMachine)(
        IVirtualBox *pThis,
        PRUnichar * nameOrId,
        IMachine * * machine
    );

    nsresult (*GetMachinesByGroups)(
        IVirtualBox *pThis,
        PRUint32 groupsSize,
        PRUnichar ** groups,
        PRUint32 *machinesSize,
        IMachine *** machines
    );

    nsresult (*GetMachineStates)(
        IVirtualBox *pThis,
        PRUint32 machinesSize,
        IMachine ** machines,
        PRUint32 *statesSize,
        PRUint32** states
    );

    nsresult (*CreateAppliance)(
        IVirtualBox *pThis,
        IAppliance * * appliance
    );

    nsresult (*CreateHardDisk)(
        IVirtualBox *pThis,
        PRUnichar * format,
        PRUnichar * location,
        IMedium * * medium
    );

    nsresult (*OpenMedium)(
        IVirtualBox *pThis,
        PRUnichar * location,
        PRUint32 deviceType,
        PRUint32 accessMode,
        PRBool forceNewUuid,
        IMedium * * medium
    );

    nsresult (*GetGuestOSType)(
        IVirtualBox *pThis,
        PRUnichar * id,
        IGuestOSType * * type
    );

    nsresult (*CreateSharedFolder)(
        IVirtualBox *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable,
        PRBool automount
    );

    nsresult (*RemoveSharedFolder)(
        IVirtualBox *pThis,
        PRUnichar * name
    );

    nsresult (*GetExtraDataKeys)(
        IVirtualBox *pThis,
        PRUint32 *keysSize,
        PRUnichar *** keys
    );

    nsresult (*GetExtraData)(
        IVirtualBox *pThis,
        PRUnichar * key,
        PRUnichar * * value
    );

    nsresult (*SetExtraData)(
        IVirtualBox *pThis,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult (*SetSettingsSecret)(
        IVirtualBox *pThis,
        PRUnichar * password
    );

    nsresult (*CreateDHCPServer)(
        IVirtualBox *pThis,
        PRUnichar * name,
        IDHCPServer * * server
    );

    nsresult (*FindDHCPServerByNetworkName)(
        IVirtualBox *pThis,
        PRUnichar * name,
        IDHCPServer * * server
    );

    nsresult (*RemoveDHCPServer)(
        IVirtualBox *pThis,
        IDHCPServer * server
    );

    nsresult (*CreateNATNetwork)(
        IVirtualBox *pThis,
        PRUnichar * networkName,
        INATNetwork * * network
    );

    nsresult (*FindNATNetworkByName)(
        IVirtualBox *pThis,
        PRUnichar * networkName,
        INATNetwork * * network
    );

    nsresult (*RemoveNATNetwork)(
        IVirtualBox *pThis,
        INATNetwork * network
    );

    nsresult (*CheckFirmwarePresent)(
        IVirtualBox *pThis,
        PRUint32 firmwareType,
        PRUnichar * version,
        PRUnichar * * url,
        PRUnichar * * file,
        PRBool * result
    );

};

struct IVirtualBox
{
    struct IVirtualBox_vtbl *vtbl;
};
/* End of struct IVirtualBox Declaration */


/* Start of struct IVFSExplorer Declaration */
#  define IVFSEXPLORER_IID_STR "fb220201-2fd3-47e2-a5dc-2c2431d833cc"
#  define IVFSEXPLORER_IID { \
    0xfb220201, 0x2fd3, 0x47e2, \
    { 0xa5, 0xdc, 0x2c, 0x24, 0x31, 0xd8, 0x33, 0xcc } \
}
struct IVFSExplorer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetPath)(IVFSExplorer *pThis, PRUnichar * *path);

    nsresult (*GetType)(IVFSExplorer *pThis, PRUint32 *type);

    nsresult (*Update)(
        IVFSExplorer *pThis,
        IProgress * * progress
    );

    nsresult (*Cd)(
        IVFSExplorer *pThis,
        PRUnichar * dir,
        IProgress * * progress
    );

    nsresult (*CdUp)(
        IVFSExplorer *pThis,
        IProgress * * progress
    );

    nsresult (*EntryList)(
        IVFSExplorer *pThis,
        PRUint32 *namesSize,
        PRUnichar *** names,
        PRUint32 *typesSize,
        PRUint32** types,
        PRUint32 *sizesSize,
        PRInt64** sizes,
        PRUint32 *modesSize,
        PRUint32** modes
    );

    nsresult (*Exists)(
        IVFSExplorer *pThis,
        PRUint32 namesSize,
        PRUnichar ** names,
        PRUint32 *existsSize,
        PRUnichar *** exists
    );

    nsresult (*Remove)(
        IVFSExplorer *pThis,
        PRUint32 namesSize,
        PRUnichar ** names,
        IProgress * * progress
    );

};

struct IVFSExplorer
{
    struct IVFSExplorer_vtbl *vtbl;
};
/* End of struct IVFSExplorer Declaration */


/* Start of struct IAppliance Declaration */
#  define IAPPLIANCE_IID_STR "3059cf9e-25c7-4f0b-9fa5-3c42e441670b"
#  define IAPPLIANCE_IID { \
    0x3059cf9e, 0x25c7, 0x4f0b, \
    { 0x9f, 0xa5, 0x3c, 0x42, 0xe4, 0x41, 0x67, 0x0b } \
}
struct IAppliance_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetPath)(IAppliance *pThis, PRUnichar * *path);

    nsresult (*GetDisks)(IAppliance *pThis, PRUint32 *disksSize, PRUnichar * **disks);

    nsresult (*GetVirtualSystemDescriptions)(IAppliance *pThis, PRUint32 *virtualSystemDescriptionsSize, IVirtualSystemDescription * **virtualSystemDescriptions);

    nsresult (*GetMachines)(IAppliance *pThis, PRUint32 *machinesSize, PRUnichar * **machines);

    nsresult (*Read)(
        IAppliance *pThis,
        PRUnichar * file,
        IProgress * * progress
    );

    nsresult (*Interpret)(IAppliance *pThis );

    nsresult (*ImportMachines)(
        IAppliance *pThis,
        PRUint32 optionsSize,
        PRUint32* options,
        IProgress * * progress
    );

    nsresult (*CreateVFSExplorer)(
        IAppliance *pThis,
        PRUnichar * URI,
        IVFSExplorer * * explorer
    );

    nsresult (*Write)(
        IAppliance *pThis,
        PRUnichar * format,
        PRUint32 optionsSize,
        PRUint32* options,
        PRUnichar * path,
        IProgress * * progress
    );

    nsresult (*GetWarnings)(
        IAppliance *pThis,
        PRUint32 *warningsSize,
        PRUnichar *** warnings
    );

};

struct IAppliance
{
    struct IAppliance_vtbl *vtbl;
};
/* End of struct IAppliance Declaration */


/* Start of struct IVirtualSystemDescription Declaration */
#  define IVIRTUALSYSTEMDESCRIPTION_IID_STR "d7525e6c-531a-4c51-8e04-41235083a3d8"
#  define IVIRTUALSYSTEMDESCRIPTION_IID { \
    0xd7525e6c, 0x531a, 0x4c51, \
    { 0x8e, 0x04, 0x41, 0x23, 0x50, 0x83, 0xa3, 0xd8 } \
}
struct IVirtualSystemDescription_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetCount)(IVirtualSystemDescription *pThis, PRUint32 *count);

    nsresult (*GetDescription)(
        IVirtualSystemDescription *pThis,
        PRUint32 *typesSize,
        PRUint32** types,
        PRUint32 *refsSize,
        PRUnichar *** refs,
        PRUint32 *OVFValuesSize,
        PRUnichar *** OVFValues,
        PRUint32 *VBoxValuesSize,
        PRUnichar *** VBoxValues,
        PRUint32 *extraConfigValuesSize,
        PRUnichar *** extraConfigValues
    );

    nsresult (*GetDescriptionByType)(
        IVirtualSystemDescription *pThis,
        PRUint32 type,
        PRUint32 *typesSize,
        PRUint32** types,
        PRUint32 *refsSize,
        PRUnichar *** refs,
        PRUint32 *OVFValuesSize,
        PRUnichar *** OVFValues,
        PRUint32 *VBoxValuesSize,
        PRUnichar *** VBoxValues,
        PRUint32 *extraConfigValuesSize,
        PRUnichar *** extraConfigValues
    );

    nsresult (*GetValuesByType)(
        IVirtualSystemDescription *pThis,
        PRUint32 type,
        PRUint32 which,
        PRUint32 *valuesSize,
        PRUnichar *** values
    );

    nsresult (*SetFinalValues)(
        IVirtualSystemDescription *pThis,
        PRUint32 enabledSize,
        PRBool* enabled,
        PRUint32 VBoxValuesSize,
        PRUnichar ** VBoxValues,
        PRUint32 extraConfigValuesSize,
        PRUnichar ** extraConfigValues
    );

    nsresult (*AddDescription)(
        IVirtualSystemDescription *pThis,
        PRUint32 type,
        PRUnichar * VBoxValue,
        PRUnichar * extraConfigValue
    );

};

struct IVirtualSystemDescription
{
    struct IVirtualSystemDescription_vtbl *vtbl;
};
/* End of struct IVirtualSystemDescription Declaration */


/* Start of struct IInternalMachineControl Declaration */
#  define IINTERNALMACHINECONTROL_IID_STR "2d9ce4b7-0ab2-4931-ac4a-e45aa66465ef"
#  define IINTERNALMACHINECONTROL_IID { \
    0x2d9ce4b7, 0x0ab2, 0x4931, \
    { 0xac, 0x4a, 0xe4, 0x5a, 0xa6, 0x64, 0x65, 0xef } \
}
struct IInternalMachineControl_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*SetRemoveSavedStateFile)(
        IInternalMachineControl *pThis,
        PRBool remove
    );

    nsresult (*UpdateState)(
        IInternalMachineControl *pThis,
        PRUint32 state
    );

    nsresult (*BeginPowerUp)(
        IInternalMachineControl *pThis,
        IProgress * progress
    );

    nsresult (*EndPowerUp)(
        IInternalMachineControl *pThis,
        PRInt32 result
    );

    nsresult (*BeginPoweringDown)(
        IInternalMachineControl *pThis,
        IProgress * * progress
    );

    nsresult (*EndPoweringDown)(
        IInternalMachineControl *pThis,
        PRInt32 result,
        PRUnichar * errMsg
    );

    nsresult (*RunUSBDeviceFilters)(
        IInternalMachineControl *pThis,
        IUSBDevice * device,
        PRBool * matched,
        PRUint32 * maskedInterfaces
    );

    nsresult (*CaptureUSBDevice)(
        IInternalMachineControl *pThis,
        PRUnichar * id
    );

    nsresult (*DetachUSBDevice)(
        IInternalMachineControl *pThis,
        PRUnichar * id,
        PRBool done
    );

    nsresult (*AutoCaptureUSBDevices)(IInternalMachineControl *pThis );

    nsresult (*DetachAllUSBDevices)(
        IInternalMachineControl *pThis,
        PRBool done
    );

    nsresult (*OnSessionEnd)(
        IInternalMachineControl *pThis,
        ISession * session,
        IProgress * * progress
    );

    nsresult (*BeginSavingState)(
        IInternalMachineControl *pThis,
        IProgress * * progress,
        PRUnichar * * stateFilePath
    );

    nsresult (*EndSavingState)(
        IInternalMachineControl *pThis,
        PRInt32 result,
        PRUnichar * errMsg
    );

    nsresult (*AdoptSavedState)(
        IInternalMachineControl *pThis,
        PRUnichar * savedStateFile
    );

    nsresult (*BeginTakingSnapshot)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        PRUnichar * name,
        PRUnichar * description,
        IProgress * consoleProgress,
        PRBool fTakingSnapshotOnline,
        PRUnichar * * stateFilePath
    );

    nsresult (*EndTakingSnapshot)(
        IInternalMachineControl *pThis,
        PRBool success
    );

    nsresult (*DeleteSnapshot)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        PRUnichar * startId,
        PRUnichar * endId,
        PRBool deleteAllChildren,
        PRUint32 * machineState,
        IProgress * * progress
    );

    nsresult (*FinishOnlineMergeMedium)(IInternalMachineControl *pThis );

    nsresult (*RestoreSnapshot)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        ISnapshot * snapshot,
        PRUint32 * machineState,
        IProgress * * progress
    );

    nsresult (*PullGuestProperties)(
        IInternalMachineControl *pThis,
        PRUint32 *namesSize,
        PRUnichar *** names,
        PRUint32 *valuesSize,
        PRUnichar *** values,
        PRUint32 *timestampsSize,
        PRInt64** timestamps,
        PRUint32 *flagsSize,
        PRUnichar *** flags
    );

    nsresult (*PushGuestProperty)(
        IInternalMachineControl *pThis,
        PRUnichar * name,
        PRUnichar * value,
        PRInt64 timestamp,
        PRUnichar * flags
    );

    nsresult (*LockMedia)(IInternalMachineControl *pThis );

    nsresult (*UnlockMedia)(IInternalMachineControl *pThis );

    nsresult (*EjectMedium)(
        IInternalMachineControl *pThis,
        IMediumAttachment * attachment,
        IMediumAttachment * * newAttachment
    );

    nsresult (*ReportVmStatistics)(
        IInternalMachineControl *pThis,
        PRUint32 validStats,
        PRUint32 cpuUser,
        PRUint32 cpuKernel,
        PRUint32 cpuIdle,
        PRUint32 memTotal,
        PRUint32 memFree,
        PRUint32 memBalloon,
        PRUint32 memShared,
        PRUint32 memCache,
        PRUint32 pagedTotal,
        PRUint32 memAllocTotal,
        PRUint32 memFreeTotal,
        PRUint32 memBalloonTotal,
        PRUint32 memSharedTotal,
        PRUint32 vmNetRx,
        PRUint32 vmNetTx
    );

};

struct IInternalMachineControl
{
    struct IInternalMachineControl_vtbl *vtbl;
};
/* End of struct IInternalMachineControl Declaration */


/* Start of struct IBIOSSettings Declaration */
#  define IBIOSSETTINGS_IID_STR "38b54279-dc35-4f5e-a431-835b867c6b5e"
#  define IBIOSSETTINGS_IID { \
    0x38b54279, 0xdc35, 0x4f5e, \
    { 0xa4, 0x31, 0x83, 0x5b, 0x86, 0x7c, 0x6b, 0x5e } \
}
struct IBIOSSettings_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetLogoFadeIn)(IBIOSSettings *pThis, PRBool *logoFadeIn);
    nsresult (*SetLogoFadeIn)(IBIOSSettings *pThis, PRBool logoFadeIn);

    nsresult (*GetLogoFadeOut)(IBIOSSettings *pThis, PRBool *logoFadeOut);
    nsresult (*SetLogoFadeOut)(IBIOSSettings *pThis, PRBool logoFadeOut);

    nsresult (*GetLogoDisplayTime)(IBIOSSettings *pThis, PRUint32 *logoDisplayTime);
    nsresult (*SetLogoDisplayTime)(IBIOSSettings *pThis, PRUint32 logoDisplayTime);

    nsresult (*GetLogoImagePath)(IBIOSSettings *pThis, PRUnichar * *logoImagePath);
    nsresult (*SetLogoImagePath)(IBIOSSettings *pThis, PRUnichar * logoImagePath);

    nsresult (*GetBootMenuMode)(IBIOSSettings *pThis, PRUint32 *bootMenuMode);
    nsresult (*SetBootMenuMode)(IBIOSSettings *pThis, PRUint32 bootMenuMode);

    nsresult (*GetACPIEnabled)(IBIOSSettings *pThis, PRBool *ACPIEnabled);
    nsresult (*SetACPIEnabled)(IBIOSSettings *pThis, PRBool ACPIEnabled);

    nsresult (*GetIOAPICEnabled)(IBIOSSettings *pThis, PRBool *IOAPICEnabled);
    nsresult (*SetIOAPICEnabled)(IBIOSSettings *pThis, PRBool IOAPICEnabled);

    nsresult (*GetTimeOffset)(IBIOSSettings *pThis, PRInt64 *timeOffset);
    nsresult (*SetTimeOffset)(IBIOSSettings *pThis, PRInt64 timeOffset);

    nsresult (*GetPXEDebugEnabled)(IBIOSSettings *pThis, PRBool *PXEDebugEnabled);
    nsresult (*SetPXEDebugEnabled)(IBIOSSettings *pThis, PRBool PXEDebugEnabled);

    nsresult (*GetNonVolatileStorageFile)(IBIOSSettings *pThis, PRUnichar * *nonVolatileStorageFile);

};

struct IBIOSSettings
{
    struct IBIOSSettings_vtbl *vtbl;
};
/* End of struct IBIOSSettings Declaration */


/* Start of struct IPCIAddress Declaration */
#  define IPCIADDRESS_IID_STR "c984d15f-e191-400b-840e-970f3dad7296"
#  define IPCIADDRESS_IID { \
    0xc984d15f, 0xe191, 0x400b, \
    { 0x84, 0x0e, 0x97, 0x0f, 0x3d, 0xad, 0x72, 0x96 } \
}
struct IPCIAddress_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetBus)(IPCIAddress *pThis, PRInt16 *bus);
    nsresult (*SetBus)(IPCIAddress *pThis, PRInt16 bus);

    nsresult (*GetDevice)(IPCIAddress *pThis, PRInt16 *device);
    nsresult (*SetDevice)(IPCIAddress *pThis, PRInt16 device);

    nsresult (*GetDevFunction)(IPCIAddress *pThis, PRInt16 *devFunction);
    nsresult (*SetDevFunction)(IPCIAddress *pThis, PRInt16 devFunction);

    nsresult (*AsLong)(
        IPCIAddress *pThis,
        PRInt32 * result
    );

    nsresult (*FromLong)(
        IPCIAddress *pThis,
        PRInt32 number
    );

};

struct IPCIAddress
{
    struct IPCIAddress_vtbl *vtbl;
};
/* End of struct IPCIAddress Declaration */


/* Start of struct IPCIDeviceAttachment Declaration */
#  define IPCIDEVICEATTACHMENT_IID_STR "91f33d6f-e621-4f70-a77e-15f0e3c714d5"
#  define IPCIDEVICEATTACHMENT_IID { \
    0x91f33d6f, 0xe621, 0x4f70, \
    { 0xa7, 0x7e, 0x15, 0xf0, 0xe3, 0xc7, 0x14, 0xd5 } \
}
struct IPCIDeviceAttachment_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IPCIDeviceAttachment *pThis, PRUnichar * *name);

    nsresult (*GetIsPhysicalDevice)(IPCIDeviceAttachment *pThis, PRBool *isPhysicalDevice);

    nsresult (*GetHostAddress)(IPCIDeviceAttachment *pThis, PRInt32 *hostAddress);

    nsresult (*GetGuestAddress)(IPCIDeviceAttachment *pThis, PRInt32 *guestAddress);

};

struct IPCIDeviceAttachment
{
    struct IPCIDeviceAttachment_vtbl *vtbl;
};
/* End of struct IPCIDeviceAttachment Declaration */


/* Start of struct IMachine Declaration */
#  define IMACHINE_IID_STR "480cf695-2d8d-4256-9c7c-cce4184fa048"
#  define IMACHINE_IID { \
    0x480cf695, 0x2d8d, 0x4256, \
    { 0x9c, 0x7c, 0xcc, 0xe4, 0x18, 0x4f, 0xa0, 0x48 } \
}
struct IMachine_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetParent)(IMachine *pThis, IVirtualBox * *parent);

    nsresult (*GetIcon)(IMachine *pThis, PRUint32 *iconSize, PRUint8 **icon);
    nsresult (*SetIcon)(IMachine *pThis, PRUint32 iconSize, PRUint8 *icon);

    nsresult (*GetAccessible)(IMachine *pThis, PRBool *accessible);

    nsresult (*GetAccessError)(IMachine *pThis, IVirtualBoxErrorInfo * *accessError);

    nsresult (*GetName)(IMachine *pThis, PRUnichar * *name);
    nsresult (*SetName)(IMachine *pThis, PRUnichar * name);

    nsresult (*GetDescription)(IMachine *pThis, PRUnichar * *description);
    nsresult (*SetDescription)(IMachine *pThis, PRUnichar * description);

    nsresult (*GetId)(IMachine *pThis, PRUnichar * *id);

    nsresult (*GetGroups)(IMachine *pThis, PRUint32 *groupsSize, PRUnichar * **groups);
    nsresult (*SetGroups)(IMachine *pThis, PRUint32 groupsSize, PRUnichar * *groups);

    nsresult (*GetOSTypeId)(IMachine *pThis, PRUnichar * *OSTypeId);
    nsresult (*SetOSTypeId)(IMachine *pThis, PRUnichar * OSTypeId);

    nsresult (*GetHardwareVersion)(IMachine *pThis, PRUnichar * *hardwareVersion);
    nsresult (*SetHardwareVersion)(IMachine *pThis, PRUnichar * hardwareVersion);

    nsresult (*GetHardwareUUID)(IMachine *pThis, PRUnichar * *hardwareUUID);
    nsresult (*SetHardwareUUID)(IMachine *pThis, PRUnichar * hardwareUUID);

    nsresult (*GetCPUCount)(IMachine *pThis, PRUint32 *CPUCount);
    nsresult (*SetCPUCount)(IMachine *pThis, PRUint32 CPUCount);

    nsresult (*GetCPUHotPlugEnabled)(IMachine *pThis, PRBool *CPUHotPlugEnabled);
    nsresult (*SetCPUHotPlugEnabled)(IMachine *pThis, PRBool CPUHotPlugEnabled);

    nsresult (*GetCPUExecutionCap)(IMachine *pThis, PRUint32 *CPUExecutionCap);
    nsresult (*SetCPUExecutionCap)(IMachine *pThis, PRUint32 CPUExecutionCap);

    nsresult (*GetMemorySize)(IMachine *pThis, PRUint32 *memorySize);
    nsresult (*SetMemorySize)(IMachine *pThis, PRUint32 memorySize);

    nsresult (*GetMemoryBalloonSize)(IMachine *pThis, PRUint32 *memoryBalloonSize);
    nsresult (*SetMemoryBalloonSize)(IMachine *pThis, PRUint32 memoryBalloonSize);

    nsresult (*GetPageFusionEnabled)(IMachine *pThis, PRBool *pageFusionEnabled);
    nsresult (*SetPageFusionEnabled)(IMachine *pThis, PRBool pageFusionEnabled);

    nsresult (*GetGraphicsControllerType)(IMachine *pThis, PRUint32 *graphicsControllerType);
    nsresult (*SetGraphicsControllerType)(IMachine *pThis, PRUint32 graphicsControllerType);

    nsresult (*GetVRAMSize)(IMachine *pThis, PRUint32 *VRAMSize);
    nsresult (*SetVRAMSize)(IMachine *pThis, PRUint32 VRAMSize);

    nsresult (*GetAccelerate3DEnabled)(IMachine *pThis, PRBool *accelerate3DEnabled);
    nsresult (*SetAccelerate3DEnabled)(IMachine *pThis, PRBool accelerate3DEnabled);

    nsresult (*GetAccelerate2DVideoEnabled)(IMachine *pThis, PRBool *accelerate2DVideoEnabled);
    nsresult (*SetAccelerate2DVideoEnabled)(IMachine *pThis, PRBool accelerate2DVideoEnabled);

    nsresult (*GetMonitorCount)(IMachine *pThis, PRUint32 *monitorCount);
    nsresult (*SetMonitorCount)(IMachine *pThis, PRUint32 monitorCount);

    nsresult (*GetVideoCaptureEnabled)(IMachine *pThis, PRBool *videoCaptureEnabled);
    nsresult (*SetVideoCaptureEnabled)(IMachine *pThis, PRBool videoCaptureEnabled);

    nsresult (*GetVideoCaptureScreens)(IMachine *pThis, PRUint32 *videoCaptureScreensSize, PRBool **videoCaptureScreens);
    nsresult (*SetVideoCaptureScreens)(IMachine *pThis, PRUint32 videoCaptureScreensSize, PRBool *videoCaptureScreens);

    nsresult (*GetVideoCaptureFile)(IMachine *pThis, PRUnichar * *videoCaptureFile);
    nsresult (*SetVideoCaptureFile)(IMachine *pThis, PRUnichar * videoCaptureFile);

    nsresult (*GetVideoCaptureWidth)(IMachine *pThis, PRUint32 *videoCaptureWidth);
    nsresult (*SetVideoCaptureWidth)(IMachine *pThis, PRUint32 videoCaptureWidth);

    nsresult (*GetVideoCaptureHeight)(IMachine *pThis, PRUint32 *videoCaptureHeight);
    nsresult (*SetVideoCaptureHeight)(IMachine *pThis, PRUint32 videoCaptureHeight);

    nsresult (*GetVideoCaptureRate)(IMachine *pThis, PRUint32 *videoCaptureRate);
    nsresult (*SetVideoCaptureRate)(IMachine *pThis, PRUint32 videoCaptureRate);

    nsresult (*GetVideoCaptureFPS)(IMachine *pThis, PRUint32 *videoCaptureFPS);
    nsresult (*SetVideoCaptureFPS)(IMachine *pThis, PRUint32 videoCaptureFPS);

    nsresult (*GetBIOSSettings)(IMachine *pThis, IBIOSSettings * *BIOSSettings);

    nsresult (*GetFirmwareType)(IMachine *pThis, PRUint32 *firmwareType);
    nsresult (*SetFirmwareType)(IMachine *pThis, PRUint32 firmwareType);

    nsresult (*GetPointingHIDType)(IMachine *pThis, PRUint32 *pointingHIDType);
    nsresult (*SetPointingHIDType)(IMachine *pThis, PRUint32 pointingHIDType);

    nsresult (*GetKeyboardHIDType)(IMachine *pThis, PRUint32 *keyboardHIDType);
    nsresult (*SetKeyboardHIDType)(IMachine *pThis, PRUint32 keyboardHIDType);

    nsresult (*GetHPETEnabled)(IMachine *pThis, PRBool *HPETEnabled);
    nsresult (*SetHPETEnabled)(IMachine *pThis, PRBool HPETEnabled);

    nsresult (*GetChipsetType)(IMachine *pThis, PRUint32 *chipsetType);
    nsresult (*SetChipsetType)(IMachine *pThis, PRUint32 chipsetType);

    nsresult (*GetSnapshotFolder)(IMachine *pThis, PRUnichar * *snapshotFolder);
    nsresult (*SetSnapshotFolder)(IMachine *pThis, PRUnichar * snapshotFolder);

    nsresult (*GetVRDEServer)(IMachine *pThis, IVRDEServer * *VRDEServer);

    nsresult (*GetEmulatedUSBCardReaderEnabled)(IMachine *pThis, PRBool *emulatedUSBCardReaderEnabled);
    nsresult (*SetEmulatedUSBCardReaderEnabled)(IMachine *pThis, PRBool emulatedUSBCardReaderEnabled);

    nsresult (*GetMediumAttachments)(IMachine *pThis, PRUint32 *mediumAttachmentsSize, IMediumAttachment * **mediumAttachments);

    nsresult (*GetUSBControllers)(IMachine *pThis, PRUint32 *USBControllersSize, IUSBController * **USBControllers);

    nsresult (*GetUSBDeviceFilters)(IMachine *pThis, IUSBDeviceFilters * *USBDeviceFilters);

    nsresult (*GetAudioAdapter)(IMachine *pThis, IAudioAdapter * *audioAdapter);

    nsresult (*GetStorageControllers)(IMachine *pThis, PRUint32 *storageControllersSize, IStorageController * **storageControllers);

    nsresult (*GetSettingsFilePath)(IMachine *pThis, PRUnichar * *settingsFilePath);

    nsresult (*GetSettingsModified)(IMachine *pThis, PRBool *settingsModified);

    nsresult (*GetSessionState)(IMachine *pThis, PRUint32 *sessionState);

    nsresult (*GetSessionType)(IMachine *pThis, PRUnichar * *sessionType);

    nsresult (*GetSessionPID)(IMachine *pThis, PRUint32 *sessionPID);

    nsresult (*GetState)(IMachine *pThis, PRUint32 *state);

    nsresult (*GetLastStateChange)(IMachine *pThis, PRInt64 *lastStateChange);

    nsresult (*GetStateFilePath)(IMachine *pThis, PRUnichar * *stateFilePath);

    nsresult (*GetLogFolder)(IMachine *pThis, PRUnichar * *logFolder);

    nsresult (*GetCurrentSnapshot)(IMachine *pThis, ISnapshot * *currentSnapshot);

    nsresult (*GetSnapshotCount)(IMachine *pThis, PRUint32 *snapshotCount);

    nsresult (*GetCurrentStateModified)(IMachine *pThis, PRBool *currentStateModified);

    nsresult (*GetSharedFolders)(IMachine *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult (*GetClipboardMode)(IMachine *pThis, PRUint32 *clipboardMode);
    nsresult (*SetClipboardMode)(IMachine *pThis, PRUint32 clipboardMode);

    nsresult (*GetDragAndDropMode)(IMachine *pThis, PRUint32 *dragAndDropMode);
    nsresult (*SetDragAndDropMode)(IMachine *pThis, PRUint32 dragAndDropMode);

    nsresult (*GetGuestPropertyNotificationPatterns)(IMachine *pThis, PRUnichar * *guestPropertyNotificationPatterns);
    nsresult (*SetGuestPropertyNotificationPatterns)(IMachine *pThis, PRUnichar * guestPropertyNotificationPatterns);

    nsresult (*GetTeleporterEnabled)(IMachine *pThis, PRBool *teleporterEnabled);
    nsresult (*SetTeleporterEnabled)(IMachine *pThis, PRBool teleporterEnabled);

    nsresult (*GetTeleporterPort)(IMachine *pThis, PRUint32 *teleporterPort);
    nsresult (*SetTeleporterPort)(IMachine *pThis, PRUint32 teleporterPort);

    nsresult (*GetTeleporterAddress)(IMachine *pThis, PRUnichar * *teleporterAddress);
    nsresult (*SetTeleporterAddress)(IMachine *pThis, PRUnichar * teleporterAddress);

    nsresult (*GetTeleporterPassword)(IMachine *pThis, PRUnichar * *teleporterPassword);
    nsresult (*SetTeleporterPassword)(IMachine *pThis, PRUnichar * teleporterPassword);

    nsresult (*GetFaultToleranceState)(IMachine *pThis, PRUint32 *faultToleranceState);
    nsresult (*SetFaultToleranceState)(IMachine *pThis, PRUint32 faultToleranceState);

    nsresult (*GetFaultTolerancePort)(IMachine *pThis, PRUint32 *faultTolerancePort);
    nsresult (*SetFaultTolerancePort)(IMachine *pThis, PRUint32 faultTolerancePort);

    nsresult (*GetFaultToleranceAddress)(IMachine *pThis, PRUnichar * *faultToleranceAddress);
    nsresult (*SetFaultToleranceAddress)(IMachine *pThis, PRUnichar * faultToleranceAddress);

    nsresult (*GetFaultTolerancePassword)(IMachine *pThis, PRUnichar * *faultTolerancePassword);
    nsresult (*SetFaultTolerancePassword)(IMachine *pThis, PRUnichar * faultTolerancePassword);

    nsresult (*GetFaultToleranceSyncInterval)(IMachine *pThis, PRUint32 *faultToleranceSyncInterval);
    nsresult (*SetFaultToleranceSyncInterval)(IMachine *pThis, PRUint32 faultToleranceSyncInterval);

    nsresult (*GetRTCUseUTC)(IMachine *pThis, PRBool *RTCUseUTC);
    nsresult (*SetRTCUseUTC)(IMachine *pThis, PRBool RTCUseUTC);

    nsresult (*GetIOCacheEnabled)(IMachine *pThis, PRBool *IOCacheEnabled);
    nsresult (*SetIOCacheEnabled)(IMachine *pThis, PRBool IOCacheEnabled);

    nsresult (*GetIOCacheSize)(IMachine *pThis, PRUint32 *IOCacheSize);
    nsresult (*SetIOCacheSize)(IMachine *pThis, PRUint32 IOCacheSize);

    nsresult (*GetPCIDeviceAssignments)(IMachine *pThis, PRUint32 *PCIDeviceAssignmentsSize, IPCIDeviceAttachment * **PCIDeviceAssignments);

    nsresult (*GetBandwidthControl)(IMachine *pThis, IBandwidthControl * *bandwidthControl);

    nsresult (*GetTracingEnabled)(IMachine *pThis, PRBool *tracingEnabled);
    nsresult (*SetTracingEnabled)(IMachine *pThis, PRBool tracingEnabled);

    nsresult (*GetTracingConfig)(IMachine *pThis, PRUnichar * *tracingConfig);
    nsresult (*SetTracingConfig)(IMachine *pThis, PRUnichar * tracingConfig);

    nsresult (*GetAllowTracingToAccessVM)(IMachine *pThis, PRBool *allowTracingToAccessVM);
    nsresult (*SetAllowTracingToAccessVM)(IMachine *pThis, PRBool allowTracingToAccessVM);

    nsresult (*GetAutostartEnabled)(IMachine *pThis, PRBool *autostartEnabled);
    nsresult (*SetAutostartEnabled)(IMachine *pThis, PRBool autostartEnabled);

    nsresult (*GetAutostartDelay)(IMachine *pThis, PRUint32 *autostartDelay);
    nsresult (*SetAutostartDelay)(IMachine *pThis, PRUint32 autostartDelay);

    nsresult (*GetAutostopType)(IMachine *pThis, PRUint32 *autostopType);
    nsresult (*SetAutostopType)(IMachine *pThis, PRUint32 autostopType);

    nsresult (*GetDefaultFrontend)(IMachine *pThis, PRUnichar * *defaultFrontend);
    nsresult (*SetDefaultFrontend)(IMachine *pThis, PRUnichar * defaultFrontend);

    nsresult (*GetUSBProxyAvailable)(IMachine *pThis, PRBool *USBProxyAvailable);

    nsresult (*LockMachine)(
        IMachine *pThis,
        ISession * session,
        PRUint32 lockType
    );

    nsresult (*LaunchVMProcess)(
        IMachine *pThis,
        ISession * session,
        PRUnichar * type,
        PRUnichar * environment,
        IProgress * * progress
    );

    nsresult (*SetBootOrder)(
        IMachine *pThis,
        PRUint32 position,
        PRUint32 device
    );

    nsresult (*GetBootOrder)(
        IMachine *pThis,
        PRUint32 position,
        PRUint32 * device
    );

    nsresult (*AttachDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        PRUint32 type,
        IMedium * medium
    );

    nsresult (*AttachDeviceWithoutMedium)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        PRUint32 type
    );

    nsresult (*DetachDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device
    );

    nsresult (*PassthroughDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        PRBool passthrough
    );

    nsresult (*TemporaryEjectDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        PRBool temporaryEject
    );

    nsresult (*NonRotationalDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        PRBool nonRotational
    );

    nsresult (*SetAutoDiscardForDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        PRBool discard
    );

    nsresult (*SetHotPluggableForDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        PRBool hotPluggable
    );

    nsresult (*SetBandwidthGroupForDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        IBandwidthGroup * bandwidthGroup
    );

    nsresult (*SetNoBandwidthGroupForDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device
    );

    nsresult (*UnmountMedium)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        PRBool force
    );

    nsresult (*MountMedium)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        IMedium * medium,
        PRBool force
    );

    nsresult (*GetMedium)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        IMedium * * medium
    );

    nsresult (*GetMediumAttachmentsOfController)(
        IMachine *pThis,
        PRUnichar * name,
        PRUint32 *mediumAttachmentsSize,
        IMediumAttachment *** mediumAttachments
    );

    nsresult (*GetMediumAttachment)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        IMediumAttachment * * attachment
    );

    nsresult (*AttachHostPCIDevice)(
        IMachine *pThis,
        PRInt32 hostAddress,
        PRInt32 desiredGuestAddress,
        PRBool tryToUnbind
    );

    nsresult (*DetachHostPCIDevice)(
        IMachine *pThis,
        PRInt32 hostAddress
    );

    nsresult (*GetNetworkAdapter)(
        IMachine *pThis,
        PRUint32 slot,
        INetworkAdapter * * adapter
    );

    nsresult (*AddStorageController)(
        IMachine *pThis,
        PRUnichar * name,
        PRUint32 connectionType,
        IStorageController * * controller
    );

    nsresult (*GetStorageControllerByName)(
        IMachine *pThis,
        PRUnichar * name,
        IStorageController * * storageController
    );

    nsresult (*GetStorageControllerByInstance)(
        IMachine *pThis,
        PRUint32 instance,
        IStorageController * * storageController
    );

    nsresult (*RemoveStorageController)(
        IMachine *pThis,
        PRUnichar * name
    );

    nsresult (*SetStorageControllerBootable)(
        IMachine *pThis,
        PRUnichar * name,
        PRBool bootable
    );

    nsresult (*AddUSBController)(
        IMachine *pThis,
        PRUnichar * name,
        PRUint32 type,
        IUSBController * * controller
    );

    nsresult (*RemoveUSBController)(
        IMachine *pThis,
        PRUnichar * name
    );

    nsresult (*GetUSBControllerByName)(
        IMachine *pThis,
        PRUnichar * name,
        IUSBController * * controller
    );

    nsresult (*GetUSBControllerCountByType)(
        IMachine *pThis,
        PRUint32 type,
        PRUint32 * controllers
    );

    nsresult (*GetSerialPort)(
        IMachine *pThis,
        PRUint32 slot,
        ISerialPort * * port
    );

    nsresult (*GetParallelPort)(
        IMachine *pThis,
        PRUint32 slot,
        IParallelPort * * port
    );

    nsresult (*GetExtraDataKeys)(
        IMachine *pThis,
        PRUint32 *keysSize,
        PRUnichar *** keys
    );

    nsresult (*GetExtraData)(
        IMachine *pThis,
        PRUnichar * key,
        PRUnichar * * value
    );

    nsresult (*SetExtraData)(
        IMachine *pThis,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult (*GetCPUProperty)(
        IMachine *pThis,
        PRUint32 property,
        PRBool * value
    );

    nsresult (*SetCPUProperty)(
        IMachine *pThis,
        PRUint32 property,
        PRBool value
    );

    nsresult (*GetCPUIDLeaf)(
        IMachine *pThis,
        PRUint32 id,
        PRUint32 * valEax,
        PRUint32 * valEbx,
        PRUint32 * valEcx,
        PRUint32 * valEdx
    );

    nsresult (*SetCPUIDLeaf)(
        IMachine *pThis,
        PRUint32 id,
        PRUint32 valEax,
        PRUint32 valEbx,
        PRUint32 valEcx,
        PRUint32 valEdx
    );

    nsresult (*RemoveCPUIDLeaf)(
        IMachine *pThis,
        PRUint32 id
    );

    nsresult (*RemoveAllCPUIDLeaves)(IMachine *pThis );

    nsresult (*GetHWVirtExProperty)(
        IMachine *pThis,
        PRUint32 property,
        PRBool * value
    );

    nsresult (*SetHWVirtExProperty)(
        IMachine *pThis,
        PRUint32 property,
        PRBool value
    );

    nsresult (*SetSettingsFilePath)(
        IMachine *pThis,
        PRUnichar * settingsFilePath,
        IProgress * * progress
    );

    nsresult (*SaveSettings)(IMachine *pThis );

    nsresult (*DiscardSettings)(IMachine *pThis );

    nsresult (*Unregister)(
        IMachine *pThis,
        PRUint32 cleanupMode,
        PRUint32 *mediaSize,
        IMedium *** media
    );

    nsresult (*DeleteConfig)(
        IMachine *pThis,
        PRUint32 mediaSize,
        IMedium ** media,
        IProgress * * progress
    );

    nsresult (*ExportTo)(
        IMachine *pThis,
        IAppliance * appliance,
        PRUnichar * location,
        IVirtualSystemDescription * * description
    );

    nsresult (*FindSnapshot)(
        IMachine *pThis,
        PRUnichar * nameOrId,
        ISnapshot * * snapshot
    );

    nsresult (*CreateSharedFolder)(
        IMachine *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable,
        PRBool automount
    );

    nsresult (*RemoveSharedFolder)(
        IMachine *pThis,
        PRUnichar * name
    );

    nsresult (*CanShowConsoleWindow)(
        IMachine *pThis,
        PRBool * canShow
    );

    nsresult (*ShowConsoleWindow)(
        IMachine *pThis,
        PRInt64 * winId
    );

    nsresult (*GetGuestProperty)(
        IMachine *pThis,
        PRUnichar * name,
        PRUnichar * * value,
        PRInt64 * timestamp,
        PRUnichar * * flags
    );

    nsresult (*GetGuestPropertyValue)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * * value
    );

    nsresult (*GetGuestPropertyTimestamp)(
        IMachine *pThis,
        PRUnichar * property,
        PRInt64 * value
    );

    nsresult (*SetGuestProperty)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * value,
        PRUnichar * flags
    );

    nsresult (*SetGuestPropertyValue)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * value
    );

    nsresult (*DeleteGuestProperty)(
        IMachine *pThis,
        PRUnichar * name
    );

    nsresult (*EnumerateGuestProperties)(
        IMachine *pThis,
        PRUnichar * patterns,
        PRUint32 *namesSize,
        PRUnichar *** names,
        PRUint32 *valuesSize,
        PRUnichar *** values,
        PRUint32 *timestampsSize,
        PRInt64** timestamps,
        PRUint32 *flagsSize,
        PRUnichar *** flags
    );

    nsresult (*QuerySavedGuestScreenInfo)(
        IMachine *pThis,
        PRUint32 screenId,
        PRUint32 * originX,
        PRUint32 * originY,
        PRUint32 * width,
        PRUint32 * height,
        PRBool * enabled
    );

    nsresult (*QuerySavedThumbnailSize)(
        IMachine *pThis,
        PRUint32 screenId,
        PRUint32 * size,
        PRUint32 * width,
        PRUint32 * height
    );

    nsresult (*ReadSavedThumbnailToArray)(
        IMachine *pThis,
        PRUint32 screenId,
        PRBool BGR,
        PRUint32 * width,
        PRUint32 * height,
        PRUint32 *dataSize,
        PRUint8** data
    );

    nsresult (*ReadSavedThumbnailPNGToArray)(
        IMachine *pThis,
        PRUint32 screenId,
        PRUint32 * width,
        PRUint32 * height,
        PRUint32 *dataSize,
        PRUint8** data
    );

    nsresult (*QuerySavedScreenshotPNGSize)(
        IMachine *pThis,
        PRUint32 screenId,
        PRUint32 * size,
        PRUint32 * width,
        PRUint32 * height
    );

    nsresult (*ReadSavedScreenshotPNGToArray)(
        IMachine *pThis,
        PRUint32 screenId,
        PRUint32 * width,
        PRUint32 * height,
        PRUint32 *dataSize,
        PRUint8** data
    );

    nsresult (*HotPlugCPU)(
        IMachine *pThis,
        PRUint32 cpu
    );

    nsresult (*HotUnplugCPU)(
        IMachine *pThis,
        PRUint32 cpu
    );

    nsresult (*GetCPUStatus)(
        IMachine *pThis,
        PRUint32 cpu,
        PRBool * attached
    );

    nsresult (*QueryLogFilename)(
        IMachine *pThis,
        PRUint32 idx,
        PRUnichar * * filename
    );

    nsresult (*ReadLog)(
        IMachine *pThis,
        PRUint32 idx,
        PRInt64 offset,
        PRInt64 size,
        PRUint32 *dataSize,
        PRUint8** data
    );

    nsresult (*CloneTo)(
        IMachine *pThis,
        IMachine * target,
        PRUint32 mode,
        PRUint32 optionsSize,
        PRUint32* options,
        IProgress * * progress
    );

};

struct IMachine
{
    struct IMachine_vtbl *vtbl;
};
/* End of struct IMachine Declaration */


/* Start of struct IEmulatedUSB Declaration */
#  define IEMULATEDUSB_IID_STR "38cc4dfd-8bb2-4d40-aebe-699eead8c2dd"
#  define IEMULATEDUSB_IID { \
    0x38cc4dfd, 0x8bb2, 0x4d40, \
    { 0xae, 0xbe, 0x69, 0x9e, 0xea, 0xd8, 0xc2, 0xdd } \
}
struct IEmulatedUSB_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetWebcams)(IEmulatedUSB *pThis, PRUint32 *webcamsSize, PRUnichar * **webcams);

    nsresult (*WebcamAttach)(
        IEmulatedUSB *pThis,
        PRUnichar * path,
        PRUnichar * settings
    );

    nsresult (*WebcamDetach)(
        IEmulatedUSB *pThis,
        PRUnichar * path
    );

};

struct IEmulatedUSB
{
    struct IEmulatedUSB_vtbl *vtbl;
};
/* End of struct IEmulatedUSB Declaration */


/* Start of struct IVRDEServerInfo Declaration */
#  define IVRDESERVERINFO_IID_STR "714434a1-58c3-4aab-9049-7652c5df113b"
#  define IVRDESERVERINFO_IID { \
    0x714434a1, 0x58c3, 0x4aab, \
    { 0x90, 0x49, 0x76, 0x52, 0xc5, 0xdf, 0x11, 0x3b } \
}
struct IVRDEServerInfo_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetActive)(IVRDEServerInfo *pThis, PRBool *active);

    nsresult (*GetPort)(IVRDEServerInfo *pThis, PRInt32 *port);

    nsresult (*GetNumberOfClients)(IVRDEServerInfo *pThis, PRUint32 *numberOfClients);

    nsresult (*GetBeginTime)(IVRDEServerInfo *pThis, PRInt64 *beginTime);

    nsresult (*GetEndTime)(IVRDEServerInfo *pThis, PRInt64 *endTime);

    nsresult (*GetBytesSent)(IVRDEServerInfo *pThis, PRInt64 *bytesSent);

    nsresult (*GetBytesSentTotal)(IVRDEServerInfo *pThis, PRInt64 *bytesSentTotal);

    nsresult (*GetBytesReceived)(IVRDEServerInfo *pThis, PRInt64 *bytesReceived);

    nsresult (*GetBytesReceivedTotal)(IVRDEServerInfo *pThis, PRInt64 *bytesReceivedTotal);

    nsresult (*GetUser)(IVRDEServerInfo *pThis, PRUnichar * *user);

    nsresult (*GetDomain)(IVRDEServerInfo *pThis, PRUnichar * *domain);

    nsresult (*GetClientName)(IVRDEServerInfo *pThis, PRUnichar * *clientName);

    nsresult (*GetClientIP)(IVRDEServerInfo *pThis, PRUnichar * *clientIP);

    nsresult (*GetClientVersion)(IVRDEServerInfo *pThis, PRUint32 *clientVersion);

    nsresult (*GetEncryptionStyle)(IVRDEServerInfo *pThis, PRUint32 *encryptionStyle);

};

struct IVRDEServerInfo
{
    struct IVRDEServerInfo_vtbl *vtbl;
};
/* End of struct IVRDEServerInfo Declaration */


/* Start of struct IConsole Declaration */
#  define ICONSOLE_IID_STR "8ab7c520-2442-4b66-8d74-4ff1e195d2b6"
#  define ICONSOLE_IID { \
    0x8ab7c520, 0x2442, 0x4b66, \
    { 0x8d, 0x74, 0x4f, 0xf1, 0xe1, 0x95, 0xd2, 0xb6 } \
}
struct IConsole_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetMachine)(IConsole *pThis, IMachine * *machine);

    nsresult (*GetState)(IConsole *pThis, PRUint32 *state);

    nsresult (*GetGuest)(IConsole *pThis, IGuest * *guest);

    nsresult (*GetKeyboard)(IConsole *pThis, IKeyboard * *keyboard);

    nsresult (*GetMouse)(IConsole *pThis, IMouse * *mouse);

    nsresult (*GetDisplay)(IConsole *pThis, IDisplay * *display);

    nsresult (*GetDebugger)(IConsole *pThis, IMachineDebugger * *debugger);

    nsresult (*GetUSBDevices)(IConsole *pThis, PRUint32 *USBDevicesSize, IUSBDevice * **USBDevices);

    nsresult (*GetRemoteUSBDevices)(IConsole *pThis, PRUint32 *remoteUSBDevicesSize, IHostUSBDevice * **remoteUSBDevices);

    nsresult (*GetSharedFolders)(IConsole *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult (*GetVRDEServerInfo)(IConsole *pThis, IVRDEServerInfo * *VRDEServerInfo);

    nsresult (*GetEventSource)(IConsole *pThis, IEventSource * *eventSource);

    nsresult (*GetAttachedPCIDevices)(IConsole *pThis, PRUint32 *attachedPCIDevicesSize, IPCIDeviceAttachment * **attachedPCIDevices);

    nsresult (*GetUseHostClipboard)(IConsole *pThis, PRBool *useHostClipboard);
    nsresult (*SetUseHostClipboard)(IConsole *pThis, PRBool useHostClipboard);

    nsresult (*GetEmulatedUSB)(IConsole *pThis, IEmulatedUSB * *emulatedUSB);

    nsresult (*PowerUp)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult (*PowerUpPaused)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult (*PowerDown)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult (*Reset)(IConsole *pThis );

    nsresult (*Pause)(IConsole *pThis );

    nsresult (*Resume)(IConsole *pThis );

    nsresult (*PowerButton)(IConsole *pThis );

    nsresult (*SleepButton)(IConsole *pThis );

    nsresult (*GetPowerButtonHandled)(
        IConsole *pThis,
        PRBool * handled
    );

    nsresult (*GetGuestEnteredACPIMode)(
        IConsole *pThis,
        PRBool * entered
    );

    nsresult (*SaveState)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult (*AdoptSavedState)(
        IConsole *pThis,
        PRUnichar * savedStateFile
    );

    nsresult (*DiscardSavedState)(
        IConsole *pThis,
        PRBool fRemoveFile
    );

    nsresult (*GetDeviceActivity)(
        IConsole *pThis,
        PRUint32 type,
        PRUint32 * activity
    );

    nsresult (*AttachUSBDevice)(
        IConsole *pThis,
        PRUnichar * id
    );

    nsresult (*DetachUSBDevice)(
        IConsole *pThis,
        PRUnichar * id,
        IUSBDevice * * device
    );

    nsresult (*FindUSBDeviceByAddress)(
        IConsole *pThis,
        PRUnichar * name,
        IUSBDevice * * device
    );

    nsresult (*FindUSBDeviceById)(
        IConsole *pThis,
        PRUnichar * id,
        IUSBDevice * * device
    );

    nsresult (*CreateSharedFolder)(
        IConsole *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable,
        PRBool automount
    );

    nsresult (*RemoveSharedFolder)(
        IConsole *pThis,
        PRUnichar * name
    );

    nsresult (*TakeSnapshot)(
        IConsole *pThis,
        PRUnichar * name,
        PRUnichar * description,
        IProgress * * progress
    );

    nsresult (*DeleteSnapshot)(
        IConsole *pThis,
        PRUnichar * id,
        IProgress * * progress
    );

    nsresult (*DeleteSnapshotAndAllChildren)(
        IConsole *pThis,
        PRUnichar * id,
        IProgress * * progress
    );

    nsresult (*DeleteSnapshotRange)(
        IConsole *pThis,
        PRUnichar * startId,
        PRUnichar * endId,
        IProgress * * progress
    );

    nsresult (*RestoreSnapshot)(
        IConsole *pThis,
        ISnapshot * snapshot,
        IProgress * * progress
    );

    nsresult (*Teleport)(
        IConsole *pThis,
        PRUnichar * hostname,
        PRUint32 tcpport,
        PRUnichar * password,
        PRUint32 maxDowntime,
        IProgress * * progress
    );

};

struct IConsole
{
    struct IConsole_vtbl *vtbl;
};
/* End of struct IConsole Declaration */


/* Start of struct IHostNetworkInterface Declaration */
#  define IHOSTNETWORKINTERFACE_IID_STR "f6e556f9-d598-409b-898c-8ba99d9b05ae"
#  define IHOSTNETWORKINTERFACE_IID { \
    0xf6e556f9, 0xd598, 0x409b, \
    { 0x89, 0x8c, 0x8b, 0xa9, 0x9d, 0x9b, 0x05, 0xae } \
}
struct IHostNetworkInterface_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IHostNetworkInterface *pThis, PRUnichar * *name);

    nsresult (*GetShortName)(IHostNetworkInterface *pThis, PRUnichar * *shortName);

    nsresult (*GetId)(IHostNetworkInterface *pThis, PRUnichar * *id);

    nsresult (*GetNetworkName)(IHostNetworkInterface *pThis, PRUnichar * *networkName);

    nsresult (*GetDHCPEnabled)(IHostNetworkInterface *pThis, PRBool *DHCPEnabled);

    nsresult (*GetIPAddress)(IHostNetworkInterface *pThis, PRUnichar * *IPAddress);

    nsresult (*GetNetworkMask)(IHostNetworkInterface *pThis, PRUnichar * *networkMask);

    nsresult (*GetIPV6Supported)(IHostNetworkInterface *pThis, PRBool *IPV6Supported);

    nsresult (*GetIPV6Address)(IHostNetworkInterface *pThis, PRUnichar * *IPV6Address);

    nsresult (*GetIPV6NetworkMaskPrefixLength)(IHostNetworkInterface *pThis, PRUint32 *IPV6NetworkMaskPrefixLength);

    nsresult (*GetHardwareAddress)(IHostNetworkInterface *pThis, PRUnichar * *hardwareAddress);

    nsresult (*GetMediumType)(IHostNetworkInterface *pThis, PRUint32 *mediumType);

    nsresult (*GetStatus)(IHostNetworkInterface *pThis, PRUint32 *status);

    nsresult (*GetInterfaceType)(IHostNetworkInterface *pThis, PRUint32 *interfaceType);

    nsresult (*EnableStaticIPConfig)(
        IHostNetworkInterface *pThis,
        PRUnichar * IPAddress,
        PRUnichar * networkMask
    );

    nsresult (*EnableStaticIPConfigV6)(
        IHostNetworkInterface *pThis,
        PRUnichar * IPV6Address,
        PRUint32 IPV6NetworkMaskPrefixLength
    );

    nsresult (*EnableDynamicIPConfig)(IHostNetworkInterface *pThis );

    nsresult (*DHCPRediscover)(IHostNetworkInterface *pThis );

};

struct IHostNetworkInterface
{
    struct IHostNetworkInterface_vtbl *vtbl;
};
/* End of struct IHostNetworkInterface Declaration */


/* Start of struct IHostVideoInputDevice Declaration */
#  define IHOSTVIDEOINPUTDEVICE_IID_STR "a1ceae44-d65e-4156-9359-d390f93ee9a0"
#  define IHOSTVIDEOINPUTDEVICE_IID { \
    0xa1ceae44, 0xd65e, 0x4156, \
    { 0x93, 0x59, 0xd3, 0x90, 0xf9, 0x3e, 0xe9, 0xa0 } \
}
struct IHostVideoInputDevice_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IHostVideoInputDevice *pThis, PRUnichar * *name);

    nsresult (*GetPath)(IHostVideoInputDevice *pThis, PRUnichar * *path);

    nsresult (*GetAlias)(IHostVideoInputDevice *pThis, PRUnichar * *alias);

};

struct IHostVideoInputDevice
{
    struct IHostVideoInputDevice_vtbl *vtbl;
};
/* End of struct IHostVideoInputDevice Declaration */


/* Start of struct IHost Declaration */
#  define IHOST_IID_STR "93269330-48ca-4096-b4a2-1189df336267"
#  define IHOST_IID { \
    0x93269330, 0x48ca, 0x4096, \
    { 0xb4, 0xa2, 0x11, 0x89, 0xdf, 0x33, 0x62, 0x67 } \
}
struct IHost_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetDVDDrives)(IHost *pThis, PRUint32 *DVDDrivesSize, IMedium * **DVDDrives);

    nsresult (*GetFloppyDrives)(IHost *pThis, PRUint32 *floppyDrivesSize, IMedium * **floppyDrives);

    nsresult (*GetUSBDevices)(IHost *pThis, PRUint32 *USBDevicesSize, IHostUSBDevice * **USBDevices);

    nsresult (*GetUSBDeviceFilters)(IHost *pThis, PRUint32 *USBDeviceFiltersSize, IHostUSBDeviceFilter * **USBDeviceFilters);

    nsresult (*GetNetworkInterfaces)(IHost *pThis, PRUint32 *networkInterfacesSize, IHostNetworkInterface * **networkInterfaces);

    nsresult (*GetNameServers)(IHost *pThis, PRUint32 *nameServersSize, PRUnichar * **nameServers);

    nsresult (*GetDomainName)(IHost *pThis, PRUnichar * *domainName);

    nsresult (*GetSearchStrings)(IHost *pThis, PRUint32 *searchStringsSize, PRUnichar * **searchStrings);

    nsresult (*GetProcessorCount)(IHost *pThis, PRUint32 *processorCount);

    nsresult (*GetProcessorOnlineCount)(IHost *pThis, PRUint32 *processorOnlineCount);

    nsresult (*GetProcessorCoreCount)(IHost *pThis, PRUint32 *processorCoreCount);

    nsresult (*GetProcessorOnlineCoreCount)(IHost *pThis, PRUint32 *processorOnlineCoreCount);

    nsresult (*GetMemorySize)(IHost *pThis, PRUint32 *memorySize);

    nsresult (*GetMemoryAvailable)(IHost *pThis, PRUint32 *memoryAvailable);

    nsresult (*GetOperatingSystem)(IHost *pThis, PRUnichar * *operatingSystem);

    nsresult (*GetOSVersion)(IHost *pThis, PRUnichar * *OSVersion);

    nsresult (*GetUTCTime)(IHost *pThis, PRInt64 *UTCTime);

    nsresult (*GetAcceleration3DAvailable)(IHost *pThis, PRBool *acceleration3DAvailable);

    nsresult (*GetVideoInputDevices)(IHost *pThis, PRUint32 *videoInputDevicesSize, IHostVideoInputDevice * **videoInputDevices);

    nsresult (*GetProcessorSpeed)(
        IHost *pThis,
        PRUint32 cpuId,
        PRUint32 * speed
    );

    nsresult (*GetProcessorFeature)(
        IHost *pThis,
        PRUint32 feature,
        PRBool * supported
    );

    nsresult (*GetProcessorDescription)(
        IHost *pThis,
        PRUint32 cpuId,
        PRUnichar * * description
    );

    nsresult (*GetProcessorCPUIDLeaf)(
        IHost *pThis,
        PRUint32 cpuId,
        PRUint32 leaf,
        PRUint32 subLeaf,
        PRUint32 * valEax,
        PRUint32 * valEbx,
        PRUint32 * valEcx,
        PRUint32 * valEdx
    );

    nsresult (*CreateHostOnlyNetworkInterface)(
        IHost *pThis,
        IHostNetworkInterface * * hostInterface,
        IProgress * * progress
    );

    nsresult (*RemoveHostOnlyNetworkInterface)(
        IHost *pThis,
        PRUnichar * id,
        IProgress * * progress
    );

    nsresult (*CreateUSBDeviceFilter)(
        IHost *pThis,
        PRUnichar * name,
        IHostUSBDeviceFilter * * filter
    );

    nsresult (*InsertUSBDeviceFilter)(
        IHost *pThis,
        PRUint32 position,
        IHostUSBDeviceFilter * filter
    );

    nsresult (*RemoveUSBDeviceFilter)(
        IHost *pThis,
        PRUint32 position
    );

    nsresult (*FindHostDVDDrive)(
        IHost *pThis,
        PRUnichar * name,
        IMedium * * drive
    );

    nsresult (*FindHostFloppyDrive)(
        IHost *pThis,
        PRUnichar * name,
        IMedium * * drive
    );

    nsresult (*FindHostNetworkInterfaceByName)(
        IHost *pThis,
        PRUnichar * name,
        IHostNetworkInterface * * networkInterface
    );

    nsresult (*FindHostNetworkInterfaceById)(
        IHost *pThis,
        PRUnichar * id,
        IHostNetworkInterface * * networkInterface
    );

    nsresult (*FindHostNetworkInterfacesOfType)(
        IHost *pThis,
        PRUint32 type,
        PRUint32 *networkInterfacesSize,
        IHostNetworkInterface *** networkInterfaces
    );

    nsresult (*FindUSBDeviceById)(
        IHost *pThis,
        PRUnichar * id,
        IHostUSBDevice * * device
    );

    nsresult (*FindUSBDeviceByAddress)(
        IHost *pThis,
        PRUnichar * name,
        IHostUSBDevice * * device
    );

    nsresult (*GenerateMACAddress)(
        IHost *pThis,
        PRUnichar * * address
    );

};

struct IHost
{
    struct IHost_vtbl *vtbl;
};
/* End of struct IHost Declaration */


/* Start of struct ISystemProperties Declaration */
#  define ISYSTEMPROPERTIES_IID_STR "1254a96a-ae57-4484-946a-22d86c1f98af"
#  define ISYSTEMPROPERTIES_IID { \
    0x1254a96a, 0xae57, 0x4484, \
    { 0x94, 0x6a, 0x22, 0xd8, 0x6c, 0x1f, 0x98, 0xaf } \
}
struct ISystemProperties_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetMinGuestRAM)(ISystemProperties *pThis, PRUint32 *minGuestRAM);

    nsresult (*GetMaxGuestRAM)(ISystemProperties *pThis, PRUint32 *maxGuestRAM);

    nsresult (*GetMinGuestVRAM)(ISystemProperties *pThis, PRUint32 *minGuestVRAM);

    nsresult (*GetMaxGuestVRAM)(ISystemProperties *pThis, PRUint32 *maxGuestVRAM);

    nsresult (*GetMinGuestCPUCount)(ISystemProperties *pThis, PRUint32 *minGuestCPUCount);

    nsresult (*GetMaxGuestCPUCount)(ISystemProperties *pThis, PRUint32 *maxGuestCPUCount);

    nsresult (*GetMaxGuestMonitors)(ISystemProperties *pThis, PRUint32 *maxGuestMonitors);

    nsresult (*GetInfoVDSize)(ISystemProperties *pThis, PRInt64 *infoVDSize);

    nsresult (*GetSerialPortCount)(ISystemProperties *pThis, PRUint32 *serialPortCount);

    nsresult (*GetParallelPortCount)(ISystemProperties *pThis, PRUint32 *parallelPortCount);

    nsresult (*GetMaxBootPosition)(ISystemProperties *pThis, PRUint32 *maxBootPosition);

    nsresult (*GetExclusiveHwVirt)(ISystemProperties *pThis, PRBool *exclusiveHwVirt);
    nsresult (*SetExclusiveHwVirt)(ISystemProperties *pThis, PRBool exclusiveHwVirt);

    nsresult (*GetDefaultMachineFolder)(ISystemProperties *pThis, PRUnichar * *defaultMachineFolder);
    nsresult (*SetDefaultMachineFolder)(ISystemProperties *pThis, PRUnichar * defaultMachineFolder);

    nsresult (*GetLoggingLevel)(ISystemProperties *pThis, PRUnichar * *loggingLevel);
    nsresult (*SetLoggingLevel)(ISystemProperties *pThis, PRUnichar * loggingLevel);

    nsresult (*GetMediumFormats)(ISystemProperties *pThis, PRUint32 *mediumFormatsSize, IMediumFormat * **mediumFormats);

    nsresult (*GetDefaultHardDiskFormat)(ISystemProperties *pThis, PRUnichar * *defaultHardDiskFormat);
    nsresult (*SetDefaultHardDiskFormat)(ISystemProperties *pThis, PRUnichar * defaultHardDiskFormat);

    nsresult (*GetFreeDiskSpaceWarning)(ISystemProperties *pThis, PRInt64 *freeDiskSpaceWarning);
    nsresult (*SetFreeDiskSpaceWarning)(ISystemProperties *pThis, PRInt64 freeDiskSpaceWarning);

    nsresult (*GetFreeDiskSpacePercentWarning)(ISystemProperties *pThis, PRUint32 *freeDiskSpacePercentWarning);
    nsresult (*SetFreeDiskSpacePercentWarning)(ISystemProperties *pThis, PRUint32 freeDiskSpacePercentWarning);

    nsresult (*GetFreeDiskSpaceError)(ISystemProperties *pThis, PRInt64 *freeDiskSpaceError);
    nsresult (*SetFreeDiskSpaceError)(ISystemProperties *pThis, PRInt64 freeDiskSpaceError);

    nsresult (*GetFreeDiskSpacePercentError)(ISystemProperties *pThis, PRUint32 *freeDiskSpacePercentError);
    nsresult (*SetFreeDiskSpacePercentError)(ISystemProperties *pThis, PRUint32 freeDiskSpacePercentError);

    nsresult (*GetVRDEAuthLibrary)(ISystemProperties *pThis, PRUnichar * *VRDEAuthLibrary);
    nsresult (*SetVRDEAuthLibrary)(ISystemProperties *pThis, PRUnichar * VRDEAuthLibrary);

    nsresult (*GetWebServiceAuthLibrary)(ISystemProperties *pThis, PRUnichar * *webServiceAuthLibrary);
    nsresult (*SetWebServiceAuthLibrary)(ISystemProperties *pThis, PRUnichar * webServiceAuthLibrary);

    nsresult (*GetDefaultVRDEExtPack)(ISystemProperties *pThis, PRUnichar * *defaultVRDEExtPack);
    nsresult (*SetDefaultVRDEExtPack)(ISystemProperties *pThis, PRUnichar * defaultVRDEExtPack);

    nsresult (*GetLogHistoryCount)(ISystemProperties *pThis, PRUint32 *logHistoryCount);
    nsresult (*SetLogHistoryCount)(ISystemProperties *pThis, PRUint32 logHistoryCount);

    nsresult (*GetDefaultAudioDriver)(ISystemProperties *pThis, PRUint32 *defaultAudioDriver);

    nsresult (*GetAutostartDatabasePath)(ISystemProperties *pThis, PRUnichar * *autostartDatabasePath);
    nsresult (*SetAutostartDatabasePath)(ISystemProperties *pThis, PRUnichar * autostartDatabasePath);

    nsresult (*GetDefaultAdditionsISO)(ISystemProperties *pThis, PRUnichar * *defaultAdditionsISO);
    nsresult (*SetDefaultAdditionsISO)(ISystemProperties *pThis, PRUnichar * defaultAdditionsISO);

    nsresult (*GetDefaultFrontend)(ISystemProperties *pThis, PRUnichar * *defaultFrontend);
    nsresult (*SetDefaultFrontend)(ISystemProperties *pThis, PRUnichar * defaultFrontend);

    nsresult (*GetMaxNetworkAdapters)(
        ISystemProperties *pThis,
        PRUint32 chipset,
        PRUint32 * maxNetworkAdapters
    );

    nsresult (*GetMaxNetworkAdaptersOfType)(
        ISystemProperties *pThis,
        PRUint32 chipset,
        PRUint32 type,
        PRUint32 * maxNetworkAdapters
    );

    nsresult (*GetMaxDevicesPerPortForStorageBus)(
        ISystemProperties *pThis,
        PRUint32 bus,
        PRUint32 * maxDevicesPerPort
    );

    nsresult (*GetMinPortCountForStorageBus)(
        ISystemProperties *pThis,
        PRUint32 bus,
        PRUint32 * minPortCount
    );

    nsresult (*GetMaxPortCountForStorageBus)(
        ISystemProperties *pThis,
        PRUint32 bus,
        PRUint32 * maxPortCount
    );

    nsresult (*GetMaxInstancesOfStorageBus)(
        ISystemProperties *pThis,
        PRUint32 chipset,
        PRUint32 bus,
        PRUint32 * maxInstances
    );

    nsresult (*GetDeviceTypesForStorageBus)(
        ISystemProperties *pThis,
        PRUint32 bus,
        PRUint32 *deviceTypesSize,
        PRUint32** deviceTypes
    );

    nsresult (*GetDefaultIoCacheSettingForStorageController)(
        ISystemProperties *pThis,
        PRUint32 controllerType,
        PRBool * enabled
    );

    nsresult (*GetMaxInstancesOfUSBControllerType)(
        ISystemProperties *pThis,
        PRUint32 chipset,
        PRUint32 type,
        PRUint32 * maxInstances
    );

};

struct ISystemProperties
{
    struct ISystemProperties_vtbl *vtbl;
};
/* End of struct ISystemProperties Declaration */


/* Start of struct IGuestOSType Declaration */
#  define IGUESTOSTYPE_IID_STR "6d968f9a-858b-4c50-bf17-241f069e94c2"
#  define IGUESTOSTYPE_IID { \
    0x6d968f9a, 0x858b, 0x4c50, \
    { 0xbf, 0x17, 0x24, 0x1f, 0x06, 0x9e, 0x94, 0xc2 } \
}
struct IGuestOSType_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetFamilyId)(IGuestOSType *pThis, PRUnichar * *familyId);

    nsresult (*GetFamilyDescription)(IGuestOSType *pThis, PRUnichar * *familyDescription);

    nsresult (*GetId)(IGuestOSType *pThis, PRUnichar * *id);

    nsresult (*GetDescription)(IGuestOSType *pThis, PRUnichar * *description);

    nsresult (*GetIs64Bit)(IGuestOSType *pThis, PRBool *is64Bit);

    nsresult (*GetRecommendedIOAPIC)(IGuestOSType *pThis, PRBool *recommendedIOAPIC);

    nsresult (*GetRecommendedVirtEx)(IGuestOSType *pThis, PRBool *recommendedVirtEx);

    nsresult (*GetRecommendedRAM)(IGuestOSType *pThis, PRUint32 *recommendedRAM);

    nsresult (*GetRecommendedVRAM)(IGuestOSType *pThis, PRUint32 *recommendedVRAM);

    nsresult (*GetRecommended2DVideoAcceleration)(IGuestOSType *pThis, PRBool *recommended2DVideoAcceleration);

    nsresult (*GetRecommended3DAcceleration)(IGuestOSType *pThis, PRBool *recommended3DAcceleration);

    nsresult (*GetRecommendedHDD)(IGuestOSType *pThis, PRInt64 *recommendedHDD);

    nsresult (*GetAdapterType)(IGuestOSType *pThis, PRUint32 *adapterType);

    nsresult (*GetRecommendedPAE)(IGuestOSType *pThis, PRBool *recommendedPAE);

    nsresult (*GetRecommendedDVDStorageController)(IGuestOSType *pThis, PRUint32 *recommendedDVDStorageController);

    nsresult (*GetRecommendedDVDStorageBus)(IGuestOSType *pThis, PRUint32 *recommendedDVDStorageBus);

    nsresult (*GetRecommendedHDStorageController)(IGuestOSType *pThis, PRUint32 *recommendedHDStorageController);

    nsresult (*GetRecommendedHDStorageBus)(IGuestOSType *pThis, PRUint32 *recommendedHDStorageBus);

    nsresult (*GetRecommendedFirmware)(IGuestOSType *pThis, PRUint32 *recommendedFirmware);

    nsresult (*GetRecommendedUSBHID)(IGuestOSType *pThis, PRBool *recommendedUSBHID);

    nsresult (*GetRecommendedHPET)(IGuestOSType *pThis, PRBool *recommendedHPET);

    nsresult (*GetRecommendedUSBTablet)(IGuestOSType *pThis, PRBool *recommendedUSBTablet);

    nsresult (*GetRecommendedRTCUseUTC)(IGuestOSType *pThis, PRBool *recommendedRTCUseUTC);

    nsresult (*GetRecommendedChipset)(IGuestOSType *pThis, PRUint32 *recommendedChipset);

    nsresult (*GetRecommendedAudioController)(IGuestOSType *pThis, PRUint32 *recommendedAudioController);

    nsresult (*GetRecommendedFloppy)(IGuestOSType *pThis, PRBool *recommendedFloppy);

    nsresult (*GetRecommendedUSB)(IGuestOSType *pThis, PRBool *recommendedUSB);

};

struct IGuestOSType
{
    struct IGuestOSType_vtbl *vtbl;
};
/* End of struct IGuestOSType Declaration */


/* Start of struct IAdditionsFacility Declaration */
#  define IADDITIONSFACILITY_IID_STR "54992946-6af1-4e49-98ec-58b558b7291e"
#  define IADDITIONSFACILITY_IID { \
    0x54992946, 0x6af1, 0x4e49, \
    { 0x98, 0xec, 0x58, 0xb5, 0x58, 0xb7, 0x29, 0x1e } \
}
struct IAdditionsFacility_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetClassType)(IAdditionsFacility *pThis, PRUint32 *classType);

    nsresult (*GetLastUpdated)(IAdditionsFacility *pThis, PRInt64 *lastUpdated);

    nsresult (*GetName)(IAdditionsFacility *pThis, PRUnichar * *name);

    nsresult (*GetStatus)(IAdditionsFacility *pThis, PRUint32 *status);

    nsresult (*GetType)(IAdditionsFacility *pThis, PRUint32 *type);

};

struct IAdditionsFacility
{
    struct IAdditionsFacility_vtbl *vtbl;
};
/* End of struct IAdditionsFacility Declaration */


/* Start of struct IGuestSession Declaration */
#  define IGUESTSESSION_IID_STR "5b28703c-07b6-4fcb-afba-ac199b309752"
#  define IGUESTSESSION_IID { \
    0x5b28703c, 0x07b6, 0x4fcb, \
    { 0xaf, 0xba, 0xac, 0x19, 0x9b, 0x30, 0x97, 0x52 } \
}
struct IGuestSession_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetUser)(IGuestSession *pThis, PRUnichar * *user);

    nsresult (*GetDomain)(IGuestSession *pThis, PRUnichar * *domain);

    nsresult (*GetName)(IGuestSession *pThis, PRUnichar * *name);

    nsresult (*GetId)(IGuestSession *pThis, PRUint32 *id);

    nsresult (*GetTimeout)(IGuestSession *pThis, PRUint32 *timeout);
    nsresult (*SetTimeout)(IGuestSession *pThis, PRUint32 timeout);

    nsresult (*GetProtocolVersion)(IGuestSession *pThis, PRUint32 *protocolVersion);

    nsresult (*GetStatus)(IGuestSession *pThis, PRUint32 *status);

    nsresult (*GetEnvironment)(IGuestSession *pThis, PRUint32 *environmentSize, PRUnichar * **environment);
    nsresult (*SetEnvironment)(IGuestSession *pThis, PRUint32 environmentSize, PRUnichar * *environment);

    nsresult (*GetProcesses)(IGuestSession *pThis, PRUint32 *processesSize, IGuestProcess * **processes);

    nsresult (*GetDirectories)(IGuestSession *pThis, PRUint32 *directoriesSize, IGuestDirectory * **directories);

    nsresult (*GetFiles)(IGuestSession *pThis, PRUint32 *filesSize, IGuestFile * **files);

    nsresult (*GetEventSource)(IGuestSession *pThis, IEventSource * *eventSource);

    nsresult (*Close)(IGuestSession *pThis );

    nsresult (*CopyFrom)(
        IGuestSession *pThis,
        PRUnichar * source,
        PRUnichar * dest,
        PRUint32 flagsSize,
        PRUint32* flags,
        IProgress * * progress
    );

    nsresult (*CopyTo)(
        IGuestSession *pThis,
        PRUnichar * source,
        PRUnichar * dest,
        PRUint32 flagsSize,
        PRUint32* flags,
        IProgress * * progress
    );

    nsresult (*DirectoryCreate)(
        IGuestSession *pThis,
        PRUnichar * path,
        PRUint32 mode,
        PRUint32 flagsSize,
        PRUint32* flags
    );

    nsresult (*DirectoryCreateTemp)(
        IGuestSession *pThis,
        PRUnichar * templateName,
        PRUint32 mode,
        PRUnichar * path,
        PRBool secure,
        PRUnichar * * directory
    );

    nsresult (*DirectoryExists)(
        IGuestSession *pThis,
        PRUnichar * path,
        PRBool * exists
    );

    nsresult (*DirectoryOpen)(
        IGuestSession *pThis,
        PRUnichar * path,
        PRUnichar * filter,
        PRUint32 flagsSize,
        PRUint32* flags,
        IGuestDirectory * * directory
    );

    nsresult (*DirectoryQueryInfo)(
        IGuestSession *pThis,
        PRUnichar * path,
        IGuestFsObjInfo * * info
    );

    nsresult (*DirectoryRemove)(
        IGuestSession *pThis,
        PRUnichar * path
    );

    nsresult (*DirectoryRemoveRecursive)(
        IGuestSession *pThis,
        PRUnichar * path,
        PRUint32 flagsSize,
        PRUint32* flags,
        IProgress * * progress
    );

    nsresult (*DirectoryRename)(
        IGuestSession *pThis,
        PRUnichar * source,
        PRUnichar * dest,
        PRUint32 flagsSize,
        PRUint32* flags
    );

    nsresult (*DirectorySetACL)(
        IGuestSession *pThis,
        PRUnichar * path,
        PRUnichar * acl
    );

    nsresult (*EnvironmentClear)(IGuestSession *pThis );

    nsresult (*EnvironmentGet)(
        IGuestSession *pThis,
        PRUnichar * name,
        PRUnichar * * value
    );

    nsresult (*EnvironmentSet)(
        IGuestSession *pThis,
        PRUnichar * name,
        PRUnichar * value
    );

    nsresult (*EnvironmentUnset)(
        IGuestSession *pThis,
        PRUnichar * name
    );

    nsresult (*FileCreateTemp)(
        IGuestSession *pThis,
        PRUnichar * templateName,
        PRUint32 mode,
        PRUnichar * path,
        PRBool secure,
        IGuestFile * * file
    );

    nsresult (*FileExists)(
        IGuestSession *pThis,
        PRUnichar * path,
        PRBool * exists
    );

    nsresult (*FileRemove)(
        IGuestSession *pThis,
        PRUnichar * path
    );

    nsresult (*FileOpen)(
        IGuestSession *pThis,
        PRUnichar * path,
        PRUnichar * openMode,
        PRUnichar * disposition,
        PRUint32 creationMode,
        IGuestFile * * file
    );

    nsresult (*FileOpenEx)(
        IGuestSession *pThis,
        PRUnichar * path,
        PRUnichar * openMode,
        PRUnichar * disposition,
        PRUnichar * sharingMode,
        PRUint32 creationMode,
        PRInt64 offset,
        IGuestFile * * file
    );

    nsresult (*FileQueryInfo)(
        IGuestSession *pThis,
        PRUnichar * path,
        IGuestFsObjInfo * * info
    );

    nsresult (*FileQuerySize)(
        IGuestSession *pThis,
        PRUnichar * path,
        PRInt64 * size
    );

    nsresult (*FileRename)(
        IGuestSession *pThis,
        PRUnichar * source,
        PRUnichar * dest,
        PRUint32 flagsSize,
        PRUint32* flags
    );

    nsresult (*FileSetACL)(
        IGuestSession *pThis,
        PRUnichar * file,
        PRUnichar * acl
    );

    nsresult (*ProcessCreate)(
        IGuestSession *pThis,
        PRUnichar * command,
        PRUint32 argumentsSize,
        PRUnichar ** arguments,
        PRUint32 environmentSize,
        PRUnichar ** environment,
        PRUint32 flagsSize,
        PRUint32* flags,
        PRUint32 timeoutMS,
        IGuestProcess * * guestProcess
    );

    nsresult (*ProcessCreateEx)(
        IGuestSession *pThis,
        PRUnichar * command,
        PRUint32 argumentsSize,
        PRUnichar ** arguments,
        PRUint32 environmentSize,
        PRUnichar ** environment,
        PRUint32 flagsSize,
        PRUint32* flags,
        PRUint32 timeoutMS,
        PRUint32 priority,
        PRUint32 affinitySize,
        PRInt32* affinity,
        IGuestProcess * * guestProcess
    );

    nsresult (*ProcessGet)(
        IGuestSession *pThis,
        PRUint32 pid,
        IGuestProcess * * guestProcess
    );

    nsresult (*SymlinkCreate)(
        IGuestSession *pThis,
        PRUnichar * source,
        PRUnichar * target,
        PRUint32 type
    );

    nsresult (*SymlinkExists)(
        IGuestSession *pThis,
        PRUnichar * symlink,
        PRBool * exists
    );

    nsresult (*SymlinkRead)(
        IGuestSession *pThis,
        PRUnichar * symlink,
        PRUint32 flagsSize,
        PRUint32* flags,
        PRUnichar * * target
    );

    nsresult (*SymlinkRemoveDirectory)(
        IGuestSession *pThis,
        PRUnichar * path
    );

    nsresult (*SymlinkRemoveFile)(
        IGuestSession *pThis,
        PRUnichar * file
    );

    nsresult (*WaitFor)(
        IGuestSession *pThis,
        PRUint32 waitFor,
        PRUint32 timeoutMS,
        PRUint32 * reason
    );

    nsresult (*WaitForArray)(
        IGuestSession *pThis,
        PRUint32 waitForSize,
        PRUint32* waitFor,
        PRUint32 timeoutMS,
        PRUint32 * reason
    );

};

struct IGuestSession
{
    struct IGuestSession_vtbl *vtbl;
};
/* End of struct IGuestSession Declaration */


/* Start of struct IProcess Declaration */
#  define IPROCESS_IID_STR "5a4fe06d-8cb1-40ff-ac9e-9676e32f706e"
#  define IPROCESS_IID { \
    0x5a4fe06d, 0x8cb1, 0x40ff, \
    { 0xac, 0x9e, 0x96, 0x76, 0xe3, 0x2f, 0x70, 0x6e } \
}
struct IProcess_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetArguments)(IProcess *pThis, PRUint32 *argumentsSize, PRUnichar * **arguments);

    nsresult (*GetEnvironment)(IProcess *pThis, PRUint32 *environmentSize, PRUnichar * **environment);

    nsresult (*GetEventSource)(IProcess *pThis, IEventSource * *eventSource);

    nsresult (*GetExecutablePath)(IProcess *pThis, PRUnichar * *executablePath);

    nsresult (*GetExitCode)(IProcess *pThis, PRInt32 *exitCode);

    nsresult (*GetName)(IProcess *pThis, PRUnichar * *name);

    nsresult (*GetPID)(IProcess *pThis, PRUint32 *PID);

    nsresult (*GetStatus)(IProcess *pThis, PRUint32 *status);

    nsresult (*WaitFor)(
        IProcess *pThis,
        PRUint32 waitFor,
        PRUint32 timeoutMS,
        PRUint32 * reason
    );

    nsresult (*WaitForArray)(
        IProcess *pThis,
        PRUint32 waitForSize,
        PRUint32* waitFor,
        PRUint32 timeoutMS,
        PRUint32 * reason
    );

    nsresult (*Read)(
        IProcess *pThis,
        PRUint32 handle,
        PRUint32 toRead,
        PRUint32 timeoutMS,
        PRUint32 *dataSize,
        PRUint8** data
    );

    nsresult (*Write)(
        IProcess *pThis,
        PRUint32 handle,
        PRUint32 flags,
        PRUint32 dataSize,
        PRUint8* data,
        PRUint32 timeoutMS,
        PRUint32 * written
    );

    nsresult (*WriteArray)(
        IProcess *pThis,
        PRUint32 handle,
        PRUint32 flagsSize,
        PRUint32* flags,
        PRUint32 dataSize,
        PRUint8* data,
        PRUint32 timeoutMS,
        PRUint32 * written
    );

    nsresult (*Terminate)(IProcess *pThis );

};

struct IProcess
{
    struct IProcess_vtbl *vtbl;
};
/* End of struct IProcess Declaration */


/* Start of struct IGuestProcess Declaration */
#  define IGUESTPROCESS_IID_STR "dfa39a36-5d43-4840-a025-67ea956b3111"
#  define IGUESTPROCESS_IID { \
    0xdfa39a36, 0x5d43, 0x4840, \
    { 0xa0, 0x25, 0x67, 0xea, 0x95, 0x6b, 0x31, 0x11 } \
}
struct IGuestProcess_vtbl
{
    struct IProcess_vtbl iprocess;

};

struct IGuestProcess
{
    struct IGuestProcess_vtbl *vtbl;
};
/* End of struct IGuestProcess Declaration */


/* Start of struct IDirectory Declaration */
#  define IDIRECTORY_IID_STR "1b70dd03-26d7-483a-8877-89bbb0f87b70"
#  define IDIRECTORY_IID { \
    0x1b70dd03, 0x26d7, 0x483a, \
    { 0x88, 0x77, 0x89, 0xbb, 0xb0, 0xf8, 0x7b, 0x70 } \
}
struct IDirectory_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetDirectoryName)(IDirectory *pThis, PRUnichar * *directoryName);

    nsresult (*GetFilter)(IDirectory *pThis, PRUnichar * *filter);

    nsresult (*Close)(IDirectory *pThis );

    nsresult (*Read)(
        IDirectory *pThis,
        IFsObjInfo * * objInfo
    );

};

struct IDirectory
{
    struct IDirectory_vtbl *vtbl;
};
/* End of struct IDirectory Declaration */


/* Start of struct IGuestDirectory Declaration */
#  define IGUESTDIRECTORY_IID_STR "af4a8ce0-0725-42b7-8826-46e3c7ba7357"
#  define IGUESTDIRECTORY_IID { \
    0xaf4a8ce0, 0x0725, 0x42b7, \
    { 0x88, 0x26, 0x46, 0xe3, 0xc7, 0xba, 0x73, 0x57 } \
}
struct IGuestDirectory_vtbl
{
    struct IDirectory_vtbl idirectory;

};

struct IGuestDirectory
{
    struct IGuestDirectory_vtbl *vtbl;
};
/* End of struct IGuestDirectory Declaration */


/* Start of struct IFile Declaration */
#  define IFILE_IID_STR "5ec56ea3-b55d-4bdb-8c4f-5f9fb26b894b"
#  define IFILE_IID { \
    0x5ec56ea3, 0xb55d, 0x4bdb, \
    { 0x8c, 0x4f, 0x5f, 0x9f, 0xb2, 0x6b, 0x89, 0x4b } \
}
struct IFile_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetCreationMode)(IFile *pThis, PRUint32 *creationMode);

    nsresult (*GetDisposition)(IFile *pThis, PRUnichar * *disposition);

    nsresult (*GetEventSource)(IFile *pThis, IEventSource * *eventSource);

    nsresult (*GetFileName)(IFile *pThis, PRUnichar * *fileName);

    nsresult (*GetId)(IFile *pThis, PRUint32 *id);

    nsresult (*GetInitialSize)(IFile *pThis, PRInt64 *initialSize);

    nsresult (*GetOpenMode)(IFile *pThis, PRUnichar * *openMode);

    nsresult (*GetOffset)(IFile *pThis, PRInt64 *offset);

    nsresult (*GetStatus)(IFile *pThis, PRUint32 *status);

    nsresult (*Close)(IFile *pThis );

    nsresult (*QueryInfo)(
        IFile *pThis,
        IFsObjInfo * * objInfo
    );

    nsresult (*Read)(
        IFile *pThis,
        PRUint32 toRead,
        PRUint32 timeoutMS,
        PRUint32 *dataSize,
        PRUint8** data
    );

    nsresult (*ReadAt)(
        IFile *pThis,
        PRInt64 offset,
        PRUint32 toRead,
        PRUint32 timeoutMS,
        PRUint32 *dataSize,
        PRUint8** data
    );

    nsresult (*Seek)(
        IFile *pThis,
        PRInt64 offset,
        PRUint32 whence
    );

    nsresult (*SetACL)(
        IFile *pThis,
        PRUnichar * acl
    );

    nsresult (*Write)(
        IFile *pThis,
        PRUint32 dataSize,
        PRUint8* data,
        PRUint32 timeoutMS,
        PRUint32 * written
    );

    nsresult (*WriteAt)(
        IFile *pThis,
        PRInt64 offset,
        PRUint32 dataSize,
        PRUint8* data,
        PRUint32 timeoutMS,
        PRUint32 * written
    );

};

struct IFile
{
    struct IFile_vtbl *vtbl;
};
/* End of struct IFile Declaration */


/* Start of struct IGuestFile Declaration */
#  define IGUESTFILE_IID_STR "60661aec-145f-4d11-b80e-8ea151598093"
#  define IGUESTFILE_IID { \
    0x60661aec, 0x145f, 0x4d11, \
    { 0xb8, 0x0e, 0x8e, 0xa1, 0x51, 0x59, 0x80, 0x93 } \
}
struct IGuestFile_vtbl
{
    struct IFile_vtbl ifile;

};

struct IGuestFile
{
    struct IGuestFile_vtbl *vtbl;
};
/* End of struct IGuestFile Declaration */


/* Start of struct IFsObjInfo Declaration */
#  define IFSOBJINFO_IID_STR "4047ba30-7006-4966-ae86-94164e5e20eb"
#  define IFSOBJINFO_IID { \
    0x4047ba30, 0x7006, 0x4966, \
    { 0xae, 0x86, 0x94, 0x16, 0x4e, 0x5e, 0x20, 0xeb } \
}
struct IFsObjInfo_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetAccessTime)(IFsObjInfo *pThis, PRInt64 *accessTime);

    nsresult (*GetAllocatedSize)(IFsObjInfo *pThis, PRInt64 *allocatedSize);

    nsresult (*GetBirthTime)(IFsObjInfo *pThis, PRInt64 *birthTime);

    nsresult (*GetChangeTime)(IFsObjInfo *pThis, PRInt64 *changeTime);

    nsresult (*GetDeviceNumber)(IFsObjInfo *pThis, PRUint32 *deviceNumber);

    nsresult (*GetFileAttributes)(IFsObjInfo *pThis, PRUnichar * *fileAttributes);

    nsresult (*GetGenerationId)(IFsObjInfo *pThis, PRUint32 *generationId);

    nsresult (*GetGID)(IFsObjInfo *pThis, PRUint32 *GID);

    nsresult (*GetGroupName)(IFsObjInfo *pThis, PRUnichar * *groupName);

    nsresult (*GetHardLinks)(IFsObjInfo *pThis, PRUint32 *hardLinks);

    nsresult (*GetModificationTime)(IFsObjInfo *pThis, PRInt64 *modificationTime);

    nsresult (*GetName)(IFsObjInfo *pThis, PRUnichar * *name);

    nsresult (*GetNodeId)(IFsObjInfo *pThis, PRInt64 *nodeId);

    nsresult (*GetNodeIdDevice)(IFsObjInfo *pThis, PRUint32 *nodeIdDevice);

    nsresult (*GetObjectSize)(IFsObjInfo *pThis, PRInt64 *objectSize);

    nsresult (*GetType)(IFsObjInfo *pThis, PRUint32 *type);

    nsresult (*GetUID)(IFsObjInfo *pThis, PRUint32 *UID);

    nsresult (*GetUserFlags)(IFsObjInfo *pThis, PRUint32 *userFlags);

    nsresult (*GetUserName)(IFsObjInfo *pThis, PRUnichar * *userName);

};

struct IFsObjInfo
{
    struct IFsObjInfo_vtbl *vtbl;
};
/* End of struct IFsObjInfo Declaration */


/* Start of struct IGuestFsObjInfo Declaration */
#  define IGUESTFSOBJINFO_IID_STR "d5cf678e-3484-4e4a-ac55-329e15462e18"
#  define IGUESTFSOBJINFO_IID { \
    0xd5cf678e, 0x3484, 0x4e4a, \
    { 0xac, 0x55, 0x32, 0x9e, 0x15, 0x46, 0x2e, 0x18 } \
}
struct IGuestFsObjInfo_vtbl
{
    struct IFsObjInfo_vtbl ifsobjinfo;

};

struct IGuestFsObjInfo
{
    struct IGuestFsObjInfo_vtbl *vtbl;
};
/* End of struct IGuestFsObjInfo Declaration */


/* Start of struct IGuest Declaration */
#  define IGUEST_IID_STR "8011a1b1-6adb-4ffb-a37e-20abdaee4650"
#  define IGUEST_IID { \
    0x8011a1b1, 0x6adb, 0x4ffb, \
    { 0xa3, 0x7e, 0x20, 0xab, 0xda, 0xee, 0x46, 0x50 } \
}
struct IGuest_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetOSTypeId)(IGuest *pThis, PRUnichar * *OSTypeId);

    nsresult (*GetAdditionsRunLevel)(IGuest *pThis, PRUint32 *additionsRunLevel);

    nsresult (*GetAdditionsVersion)(IGuest *pThis, PRUnichar * *additionsVersion);

    nsresult (*GetAdditionsRevision)(IGuest *pThis, PRUint32 *additionsRevision);

    nsresult (*GetEventSource)(IGuest *pThis, IEventSource * *eventSource);

    nsresult (*GetFacilities)(IGuest *pThis, PRUint32 *facilitiesSize, IAdditionsFacility * **facilities);

    nsresult (*GetSessions)(IGuest *pThis, PRUint32 *sessionsSize, IGuestSession * **sessions);

    nsresult (*GetMemoryBalloonSize)(IGuest *pThis, PRUint32 *memoryBalloonSize);
    nsresult (*SetMemoryBalloonSize)(IGuest *pThis, PRUint32 memoryBalloonSize);

    nsresult (*GetStatisticsUpdateInterval)(IGuest *pThis, PRUint32 *statisticsUpdateInterval);
    nsresult (*SetStatisticsUpdateInterval)(IGuest *pThis, PRUint32 statisticsUpdateInterval);

    nsresult (*InternalGetStatistics)(
        IGuest *pThis,
        PRUint32 * cpuUser,
        PRUint32 * cpuKernel,
        PRUint32 * cpuIdle,
        PRUint32 * memTotal,
        PRUint32 * memFree,
        PRUint32 * memBalloon,
        PRUint32 * memShared,
        PRUint32 * memCache,
        PRUint32 * pagedTotal,
        PRUint32 * memAllocTotal,
        PRUint32 * memFreeTotal,
        PRUint32 * memBalloonTotal,
        PRUint32 * memSharedTotal
    );

    nsresult (*GetFacilityStatus)(
        IGuest *pThis,
        PRUint32 facility,
        PRInt64 * timestamp,
        PRUint32 * status
    );

    nsresult (*GetAdditionsStatus)(
        IGuest *pThis,
        PRUint32 level,
        PRBool * active
    );

    nsresult (*SetCredentials)(
        IGuest *pThis,
        PRUnichar * userName,
        PRUnichar * password,
        PRUnichar * domain,
        PRBool allowInteractiveLogon
    );

    nsresult (*DragHGEnter)(
        IGuest *pThis,
        PRUint32 screenId,
        PRUint32 y,
        PRUint32 x,
        PRUint32 defaultAction,
        PRUint32 allowedActionsSize,
        PRUint32* allowedActions,
        PRUint32 formatsSize,
        PRUnichar ** formats,
        PRUint32 * resultAction
    );

    nsresult (*DragHGMove)(
        IGuest *pThis,
        PRUint32 screenId,
        PRUint32 x,
        PRUint32 y,
        PRUint32 defaultAction,
        PRUint32 allowedActionsSize,
        PRUint32* allowedActions,
        PRUint32 formatsSize,
        PRUnichar ** formats,
        PRUint32 * resultAction
    );

    nsresult (*DragHGLeave)(
        IGuest *pThis,
        PRUint32 screenId
    );

    nsresult (*DragHGDrop)(
        IGuest *pThis,
        PRUint32 screenId,
        PRUint32 x,
        PRUint32 y,
        PRUint32 defaultAction,
        PRUint32 allowedActionsSize,
        PRUint32* allowedActions,
        PRUint32 formatsSize,
        PRUnichar ** formats,
        PRUnichar * * format,
        PRUint32 * resultAction
    );

    nsresult (*DragHGPutData)(
        IGuest *pThis,
        PRUint32 screenId,
        PRUnichar * format,
        PRUint32 dataSize,
        PRUint8* data,
        IProgress * * progress
    );

    nsresult (*DragGHPending)(
        IGuest *pThis,
        PRUint32 screenId,
        PRUint32 *formatsSize,
        PRUnichar *** formats,
        PRUint32 *allowedActionsSize,
        PRUint32** allowedActions,
        PRUint32 * defaultAction
    );

    nsresult (*DragGHDropped)(
        IGuest *pThis,
        PRUnichar * format,
        PRUint32 action,
        IProgress * * progress
    );

    nsresult (*DragGHGetData)(
        IGuest *pThis,
        PRUint32 *dataSize,
        PRUint8** data
    );

    nsresult (*CreateSession)(
        IGuest *pThis,
        PRUnichar * user,
        PRUnichar * password,
        PRUnichar * domain,
        PRUnichar * sessionName,
        IGuestSession * * guestSession
    );

    nsresult (*FindSession)(
        IGuest *pThis,
        PRUnichar * sessionName,
        PRUint32 *sessionsSize,
        IGuestSession *** sessions
    );

    nsresult (*UpdateGuestAdditions)(
        IGuest *pThis,
        PRUnichar * source,
        PRUint32 argumentsSize,
        PRUnichar ** arguments,
        PRUint32 flagsSize,
        PRUint32* flags,
        IProgress * * progress
    );

};

struct IGuest
{
    struct IGuest_vtbl *vtbl;
};
/* End of struct IGuest Declaration */


/* Start of struct IProgress Declaration */
#  define IPROGRESS_IID_STR "c20238e4-3221-4d3f-8891-81ce92d9f913"
#  define IPROGRESS_IID { \
    0xc20238e4, 0x3221, 0x4d3f, \
    { 0x88, 0x91, 0x81, 0xce, 0x92, 0xd9, 0xf9, 0x13 } \
}
struct IProgress_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetId)(IProgress *pThis, PRUnichar * *id);

    nsresult (*GetDescription)(IProgress *pThis, PRUnichar * *description);

    nsresult (*GetInitiator)(IProgress *pThis, nsISupports * *initiator);

    nsresult (*GetCancelable)(IProgress *pThis, PRBool *cancelable);

    nsresult (*GetPercent)(IProgress *pThis, PRUint32 *percent);

    nsresult (*GetTimeRemaining)(IProgress *pThis, PRInt32 *timeRemaining);

    nsresult (*GetCompleted)(IProgress *pThis, PRBool *completed);

    nsresult (*GetCanceled)(IProgress *pThis, PRBool *canceled);

    nsresult (*GetResultCode)(IProgress *pThis, PRInt32 *resultCode);

    nsresult (*GetErrorInfo)(IProgress *pThis, IVirtualBoxErrorInfo * *errorInfo);

    nsresult (*GetOperationCount)(IProgress *pThis, PRUint32 *operationCount);

    nsresult (*GetOperation)(IProgress *pThis, PRUint32 *operation);

    nsresult (*GetOperationDescription)(IProgress *pThis, PRUnichar * *operationDescription);

    nsresult (*GetOperationPercent)(IProgress *pThis, PRUint32 *operationPercent);

    nsresult (*GetOperationWeight)(IProgress *pThis, PRUint32 *operationWeight);

    nsresult (*GetTimeout)(IProgress *pThis, PRUint32 *timeout);
    nsresult (*SetTimeout)(IProgress *pThis, PRUint32 timeout);

    nsresult (*SetCurrentOperationProgress)(
        IProgress *pThis,
        PRUint32 percent
    );

    nsresult (*SetNextOperation)(
        IProgress *pThis,
        PRUnichar * nextOperationDescription,
        PRUint32 nextOperationsWeight
    );

    nsresult (*WaitForCompletion)(
        IProgress *pThis,
        PRInt32 timeout
    );

    nsresult (*WaitForOperationCompletion)(
        IProgress *pThis,
        PRUint32 operation,
        PRInt32 timeout
    );

    nsresult (*WaitForAsyncProgressCompletion)(
        IProgress *pThis,
        IProgress * pProgressAsync
    );

    nsresult (*Cancel)(IProgress *pThis );

};

struct IProgress
{
    struct IProgress_vtbl *vtbl;
};
/* End of struct IProgress Declaration */


/* Start of struct ISnapshot Declaration */
#  define ISNAPSHOT_IID_STR "0472823b-c6e7-472a-8e9f-d732e86b8463"
#  define ISNAPSHOT_IID { \
    0x0472823b, 0xc6e7, 0x472a, \
    { 0x8e, 0x9f, 0xd7, 0x32, 0xe8, 0x6b, 0x84, 0x63 } \
}
struct ISnapshot_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetId)(ISnapshot *pThis, PRUnichar * *id);

    nsresult (*GetName)(ISnapshot *pThis, PRUnichar * *name);
    nsresult (*SetName)(ISnapshot *pThis, PRUnichar * name);

    nsresult (*GetDescription)(ISnapshot *pThis, PRUnichar * *description);
    nsresult (*SetDescription)(ISnapshot *pThis, PRUnichar * description);

    nsresult (*GetTimeStamp)(ISnapshot *pThis, PRInt64 *timeStamp);

    nsresult (*GetOnline)(ISnapshot *pThis, PRBool *online);

    nsresult (*GetMachine)(ISnapshot *pThis, IMachine * *machine);

    nsresult (*GetParent)(ISnapshot *pThis, ISnapshot * *parent);

    nsresult (*GetChildren)(ISnapshot *pThis, PRUint32 *childrenSize, ISnapshot * **children);

    nsresult (*GetChildrenCount)(
        ISnapshot *pThis,
        PRUint32 * childrenCount
    );

};

struct ISnapshot
{
    struct ISnapshot_vtbl *vtbl;
};
/* End of struct ISnapshot Declaration */


/* Start of struct IMediumAttachment Declaration */
#  define IMEDIUMATTACHMENT_IID_STR "4b252567-5d4e-4db8-b3c8-569ec1c9236c"
#  define IMEDIUMATTACHMENT_IID { \
    0x4b252567, 0x5d4e, 0x4db8, \
    { 0xb3, 0xc8, 0x56, 0x9e, 0xc1, 0xc9, 0x23, 0x6c } \
}
struct IMediumAttachment_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetMedium)(IMediumAttachment *pThis, IMedium * *medium);

    nsresult (*GetController)(IMediumAttachment *pThis, PRUnichar * *controller);

    nsresult (*GetPort)(IMediumAttachment *pThis, PRInt32 *port);

    nsresult (*GetDevice)(IMediumAttachment *pThis, PRInt32 *device);

    nsresult (*GetType)(IMediumAttachment *pThis, PRUint32 *type);

    nsresult (*GetPassthrough)(IMediumAttachment *pThis, PRBool *passthrough);

    nsresult (*GetTemporaryEject)(IMediumAttachment *pThis, PRBool *temporaryEject);

    nsresult (*GetIsEjected)(IMediumAttachment *pThis, PRBool *isEjected);

    nsresult (*GetNonRotational)(IMediumAttachment *pThis, PRBool *nonRotational);

    nsresult (*GetDiscard)(IMediumAttachment *pThis, PRBool *discard);

    nsresult (*GetHotPluggable)(IMediumAttachment *pThis, PRBool *hotPluggable);

    nsresult (*GetBandwidthGroup)(IMediumAttachment *pThis, IBandwidthGroup * *bandwidthGroup);

};

struct IMediumAttachment
{
    struct IMediumAttachment_vtbl *vtbl;
};
/* End of struct IMediumAttachment Declaration */


/* Start of struct IMedium Declaration */
#  define IMEDIUM_IID_STR "05f2bbb6-a3a6-4fb9-9b49-6d0dda7142ac"
#  define IMEDIUM_IID { \
    0x05f2bbb6, 0xa3a6, 0x4fb9, \
    { 0x9b, 0x49, 0x6d, 0x0d, 0xda, 0x71, 0x42, 0xac } \
}
struct IMedium_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetId)(IMedium *pThis, PRUnichar * *id);

    nsresult (*GetDescription)(IMedium *pThis, PRUnichar * *description);
    nsresult (*SetDescription)(IMedium *pThis, PRUnichar * description);

    nsresult (*GetState)(IMedium *pThis, PRUint32 *state);

    nsresult (*GetVariant)(IMedium *pThis, PRUint32 *variantSize, PRUint32 **variant);

    nsresult (*GetLocation)(IMedium *pThis, PRUnichar * *location);

    nsresult (*GetName)(IMedium *pThis, PRUnichar * *name);

    nsresult (*GetDeviceType)(IMedium *pThis, PRUint32 *deviceType);

    nsresult (*GetHostDrive)(IMedium *pThis, PRBool *hostDrive);

    nsresult (*GetSize)(IMedium *pThis, PRInt64 *size);

    nsresult (*GetFormat)(IMedium *pThis, PRUnichar * *format);

    nsresult (*GetMediumFormat)(IMedium *pThis, IMediumFormat * *mediumFormat);

    nsresult (*GetType)(IMedium *pThis, PRUint32 *type);
    nsresult (*SetType)(IMedium *pThis, PRUint32 type);

    nsresult (*GetAllowedTypes)(IMedium *pThis, PRUint32 *allowedTypesSize, PRUint32 **allowedTypes);

    nsresult (*GetParent)(IMedium *pThis, IMedium * *parent);

    nsresult (*GetChildren)(IMedium *pThis, PRUint32 *childrenSize, IMedium * **children);

    nsresult (*GetBase)(IMedium *pThis, IMedium * *base);

    nsresult (*GetReadOnly)(IMedium *pThis, PRBool *readOnly);

    nsresult (*GetLogicalSize)(IMedium *pThis, PRInt64 *logicalSize);

    nsresult (*GetAutoReset)(IMedium *pThis, PRBool *autoReset);
    nsresult (*SetAutoReset)(IMedium *pThis, PRBool autoReset);

    nsresult (*GetLastAccessError)(IMedium *pThis, PRUnichar * *lastAccessError);

    nsresult (*GetMachineIds)(IMedium *pThis, PRUint32 *machineIdsSize, PRUnichar * **machineIds);

    nsresult (*SetIds)(
        IMedium *pThis,
        PRBool setImageId,
        PRUnichar * imageId,
        PRBool setParentId,
        PRUnichar * parentId
    );

    nsresult (*RefreshState)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult (*GetSnapshotIds)(
        IMedium *pThis,
        PRUnichar * machineId,
        PRUint32 *snapshotIdsSize,
        PRUnichar *** snapshotIds
    );

    nsresult (*LockRead)(
        IMedium *pThis,
        IToken * * token
    );

    nsresult (*LockWrite)(
        IMedium *pThis,
        IToken * * token
    );

    nsresult (*Close)(IMedium *pThis );

    nsresult (*GetProperty)(
        IMedium *pThis,
        PRUnichar * name,
        PRUnichar * * value
    );

    nsresult (*SetProperty)(
        IMedium *pThis,
        PRUnichar * name,
        PRUnichar * value
    );

    nsresult (*GetProperties)(
        IMedium *pThis,
        PRUnichar * names,
        PRUint32 *returnNamesSize,
        PRUnichar *** returnNames,
        PRUint32 *returnValuesSize,
        PRUnichar *** returnValues
    );

    nsresult (*SetProperties)(
        IMedium *pThis,
        PRUint32 namesSize,
        PRUnichar ** names,
        PRUint32 valuesSize,
        PRUnichar ** values
    );

    nsresult (*CreateBaseStorage)(
        IMedium *pThis,
        PRInt64 logicalSize,
        PRUint32 variantSize,
        PRUint32* variant,
        IProgress * * progress
    );

    nsresult (*DeleteStorage)(
        IMedium *pThis,
        IProgress * * progress
    );

    nsresult (*CreateDiffStorage)(
        IMedium *pThis,
        IMedium * target,
        PRUint32 variantSize,
        PRUint32* variant,
        IProgress * * progress
    );

    nsresult (*MergeTo)(
        IMedium *pThis,
        IMedium * target,
        IProgress * * progress
    );

    nsresult (*CloneTo)(
        IMedium *pThis,
        IMedium * target,
        PRUint32 variantSize,
        PRUint32* variant,
        IMedium * parent,
        IProgress * * progress
    );

    nsresult (*CloneToBase)(
        IMedium *pThis,
        IMedium * target,
        PRUint32 variantSize,
        PRUint32* variant,
        IProgress * * progress
    );

    nsresult (*SetLocation)(
        IMedium *pThis,
        PRUnichar * location,
        IProgress * * progress
    );

    nsresult (*Compact)(
        IMedium *pThis,
        IProgress * * progress
    );

    nsresult (*Resize)(
        IMedium *pThis,
        PRInt64 logicalSize,
        IProgress * * progress
    );

    nsresult (*Reset)(
        IMedium *pThis,
        IProgress * * progress
    );

};

struct IMedium
{
    struct IMedium_vtbl *vtbl;
};
/* End of struct IMedium Declaration */


/* Start of struct IMediumFormat Declaration */
#  define IMEDIUMFORMAT_IID_STR "6238e1cf-a17d-4ec1-8172-418bfb22b93a"
#  define IMEDIUMFORMAT_IID { \
    0x6238e1cf, 0xa17d, 0x4ec1, \
    { 0x81, 0x72, 0x41, 0x8b, 0xfb, 0x22, 0xb9, 0x3a } \
}
struct IMediumFormat_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetId)(IMediumFormat *pThis, PRUnichar * *id);

    nsresult (*GetName)(IMediumFormat *pThis, PRUnichar * *name);

    nsresult (*GetCapabilities)(IMediumFormat *pThis, PRUint32 *capabilitiesSize, PRUint32 **capabilities);

    nsresult (*DescribeFileExtensions)(
        IMediumFormat *pThis,
        PRUint32 *extensionsSize,
        PRUnichar *** extensions,
        PRUint32 *typesSize,
        PRUint32** types
    );

    nsresult (*DescribeProperties)(
        IMediumFormat *pThis,
        PRUint32 *namesSize,
        PRUnichar *** names,
        PRUint32 *descriptionsSize,
        PRUnichar *** descriptions,
        PRUint32 *typesSize,
        PRUint32** types,
        PRUint32 *flagsSize,
        PRUint32** flags,
        PRUint32 *defaultsSize,
        PRUnichar *** defaults
    );

};

struct IMediumFormat
{
    struct IMediumFormat_vtbl *vtbl;
};
/* End of struct IMediumFormat Declaration */


/* Start of struct IToken Declaration */
#  define ITOKEN_IID_STR "3b1c4797-e289-4d4c-b74c-50c9b86a36f8"
#  define ITOKEN_IID { \
    0x3b1c4797, 0xe289, 0x4d4c, \
    { 0xb7, 0x4c, 0x50, 0xc9, 0xb8, 0x6a, 0x36, 0xf8 } \
}
struct IToken_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*Abandon)(IToken *pThis );

    nsresult (*Dummy)(IToken *pThis );

};

struct IToken
{
    struct IToken_vtbl *vtbl;
};
/* End of struct IToken Declaration */


/* Start of struct IKeyboard Declaration */
#  define IKEYBOARD_IID_STR "f6916ec5-a881-4237-898f-7de58cf88672"
#  define IKEYBOARD_IID { \
    0xf6916ec5, 0xa881, 0x4237, \
    { 0x89, 0x8f, 0x7d, 0xe5, 0x8c, 0xf8, 0x86, 0x72 } \
}
struct IKeyboard_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetEventSource)(IKeyboard *pThis, IEventSource * *eventSource);

    nsresult (*PutScancode)(
        IKeyboard *pThis,
        PRInt32 scancode
    );

    nsresult (*PutScancodes)(
        IKeyboard *pThis,
        PRUint32 scancodesSize,
        PRInt32* scancodes,
        PRUint32 * codesStored
    );

    nsresult (*PutCAD)(IKeyboard *pThis );

};

struct IKeyboard
{
    struct IKeyboard_vtbl *vtbl;
};
/* End of struct IKeyboard Declaration */


/* Start of struct IMouse Declaration */
#  define IMOUSE_IID_STR "ee770393-415f-4421-b2d5-28b73cacf86a"
#  define IMOUSE_IID { \
    0xee770393, 0x415f, 0x4421, \
    { 0xb2, 0xd5, 0x28, 0xb7, 0x3c, 0xac, 0xf8, 0x6a } \
}
struct IMouse_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetAbsoluteSupported)(IMouse *pThis, PRBool *absoluteSupported);

    nsresult (*GetRelativeSupported)(IMouse *pThis, PRBool *relativeSupported);

    nsresult (*GetMultiTouchSupported)(IMouse *pThis, PRBool *multiTouchSupported);

    nsresult (*GetNeedsHostCursor)(IMouse *pThis, PRBool *needsHostCursor);

    nsresult (*GetEventSource)(IMouse *pThis, IEventSource * *eventSource);

    nsresult (*PutMouseEvent)(
        IMouse *pThis,
        PRInt32 dx,
        PRInt32 dy,
        PRInt32 dz,
        PRInt32 dw,
        PRInt32 buttonState
    );

    nsresult (*PutMouseEventAbsolute)(
        IMouse *pThis,
        PRInt32 x,
        PRInt32 y,
        PRInt32 dz,
        PRInt32 dw,
        PRInt32 buttonState
    );

    nsresult (*PutEventMultiTouch)(
        IMouse *pThis,
        PRInt32 count,
        PRUint32 contactsSize,
        PRInt64* contacts,
        PRUint32 scanTime
    );

    nsresult (*PutEventMultiTouchString)(
        IMouse *pThis,
        PRInt32 count,
        PRUnichar * contacts,
        PRUint32 scanTime
    );

};

struct IMouse
{
    struct IMouse_vtbl *vtbl;
};
/* End of struct IMouse Declaration */


/* Start of struct IFramebuffer Declaration */
#  define IFRAMEBUFFER_IID_STR "e3f122c0-adab-4fc9-a8dc-da112fb48428"
#  define IFRAMEBUFFER_IID { \
    0xe3f122c0, 0xadab, 0x4fc9, \
    { 0xa8, 0xdc, 0xda, 0x11, 0x2f, 0xb4, 0x84, 0x28 } \
}
struct IFramebuffer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetAddress)(IFramebuffer *pThis, PRUint8 * *address);

    nsresult (*GetWidth)(IFramebuffer *pThis, PRUint32 *width);

    nsresult (*GetHeight)(IFramebuffer *pThis, PRUint32 *height);

    nsresult (*GetBitsPerPixel)(IFramebuffer *pThis, PRUint32 *bitsPerPixel);

    nsresult (*GetBytesPerLine)(IFramebuffer *pThis, PRUint32 *bytesPerLine);

    nsresult (*GetPixelFormat)(IFramebuffer *pThis, PRUint32 *pixelFormat);

    nsresult (*GetUsesGuestVRAM)(IFramebuffer *pThis, PRBool *usesGuestVRAM);

    nsresult (*GetHeightReduction)(IFramebuffer *pThis, PRUint32 *heightReduction);

    nsresult (*GetOverlay)(IFramebuffer *pThis, IFramebufferOverlay * *overlay);

    nsresult (*GetWinId)(IFramebuffer *pThis, PRInt64 *winId);

    nsresult (*Lock)(IFramebuffer *pThis );

    nsresult (*Unlock)(IFramebuffer *pThis );

    nsresult (*NotifyUpdate)(
        IFramebuffer *pThis,
        PRUint32 x,
        PRUint32 y,
        PRUint32 width,
        PRUint32 height
    );

    nsresult (*RequestResize)(
        IFramebuffer *pThis,
        PRUint32 screenId,
        PRUint32 pixelFormat,
        PRUint8 * VRAM,
        PRUint32 bitsPerPixel,
        PRUint32 bytesPerLine,
        PRUint32 width,
        PRUint32 height,
        PRBool * finished
    );

    nsresult (*VideoModeSupported)(
        IFramebuffer *pThis,
        PRUint32 width,
        PRUint32 height,
        PRUint32 bpp,
        PRBool * supported
    );

    nsresult (*GetVisibleRegion)(
        IFramebuffer *pThis,
        PRUint8 * rectangles,
        PRUint32 count,
        PRUint32 * countCopied
    );

    nsresult (*SetVisibleRegion)(
        IFramebuffer *pThis,
        PRUint8 * rectangles,
        PRUint32 count
    );

    nsresult (*ProcessVHWACommand)(
        IFramebuffer *pThis,
        PRUint8 * command
    );

    nsresult (*Notify3DEvent)(
        IFramebuffer *pThis,
        PRUint32 type,
        PRUint8 * data
    );

};

struct IFramebuffer
{
    struct IFramebuffer_vtbl *vtbl;
};
/* End of struct IFramebuffer Declaration */


/* Start of struct IFramebufferOverlay Declaration */
#  define IFRAMEBUFFEROVERLAY_IID_STR "0bcc1c7e-e415-47d2-bfdb-e4c705fb0f47"
#  define IFRAMEBUFFEROVERLAY_IID { \
    0x0bcc1c7e, 0xe415, 0x47d2, \
    { 0xbf, 0xdb, 0xe4, 0xc7, 0x05, 0xfb, 0x0f, 0x47 } \
}
struct IFramebufferOverlay_vtbl
{
    struct IFramebuffer_vtbl iframebuffer;

    nsresult (*GetX)(IFramebufferOverlay *pThis, PRUint32 *x);

    nsresult (*GetY)(IFramebufferOverlay *pThis, PRUint32 *y);

    nsresult (*GetVisible)(IFramebufferOverlay *pThis, PRBool *visible);
    nsresult (*SetVisible)(IFramebufferOverlay *pThis, PRBool visible);

    nsresult (*GetAlpha)(IFramebufferOverlay *pThis, PRUint32 *alpha);
    nsresult (*SetAlpha)(IFramebufferOverlay *pThis, PRUint32 alpha);

    nsresult (*Move)(
        IFramebufferOverlay *pThis,
        PRUint32 x,
        PRUint32 y
    );

};

struct IFramebufferOverlay
{
    struct IFramebufferOverlay_vtbl *vtbl;
};
/* End of struct IFramebufferOverlay Declaration */


/* Start of struct IDisplay Declaration */
#  define IDISPLAY_IID_STR "480b372c-c0b5-4c23-9bd7-dcbb85b1594c"
#  define IDISPLAY_IID { \
    0x480b372c, 0xc0b5, 0x4c23, \
    { 0x9b, 0xd7, 0xdc, 0xbb, 0x85, 0xb1, 0x59, 0x4c } \
}
struct IDisplay_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetScreenResolution)(
        IDisplay *pThis,
        PRUint32 screenId,
        PRUint32 * width,
        PRUint32 * height,
        PRUint32 * bitsPerPixel,
        PRInt32 * xOrigin,
        PRInt32 * yOrigin
    );

    nsresult (*SetFramebuffer)(
        IDisplay *pThis,
        PRUint32 screenId,
        IFramebuffer * framebuffer
    );

    nsresult (*GetFramebuffer)(
        IDisplay *pThis,
        PRUint32 screenId,
        IFramebuffer * * framebuffer,
        PRInt32 * xOrigin,
        PRInt32 * yOrigin
    );

    nsresult (*SetVideoModeHint)(
        IDisplay *pThis,
        PRUint32 display,
        PRBool enabled,
        PRBool changeOrigin,
        PRInt32 originX,
        PRInt32 originY,
        PRUint32 width,
        PRUint32 height,
        PRUint32 bitsPerPixel
    );

    nsresult (*SetSeamlessMode)(
        IDisplay *pThis,
        PRBool enabled
    );

    nsresult (*TakeScreenShot)(
        IDisplay *pThis,
        PRUint32 screenId,
        PRUint8 * address,
        PRUint32 width,
        PRUint32 height
    );

    nsresult (*TakeScreenShotToArray)(
        IDisplay *pThis,
        PRUint32 screenId,
        PRUint32 width,
        PRUint32 height,
        PRUint32 *screenDataSize,
        PRUint8** screenData
    );

    nsresult (*TakeScreenShotPNGToArray)(
        IDisplay *pThis,
        PRUint32 screenId,
        PRUint32 width,
        PRUint32 height,
        PRUint32 *screenDataSize,
        PRUint8** screenData
    );

    nsresult (*DrawToScreen)(
        IDisplay *pThis,
        PRUint32 screenId,
        PRUint8 * address,
        PRUint32 x,
        PRUint32 y,
        PRUint32 width,
        PRUint32 height
    );

    nsresult (*InvalidateAndUpdate)(IDisplay *pThis );

    nsresult (*ResizeCompleted)(
        IDisplay *pThis,
        PRUint32 screenId
    );

    nsresult (*CompleteVHWACommand)(
        IDisplay *pThis,
        PRUint8 * command
    );

    nsresult (*ViewportChanged)(
        IDisplay *pThis,
        PRUint32 screenId,
        PRUint32 x,
        PRUint32 y,
        PRUint32 width,
        PRUint32 height
    );

};

struct IDisplay
{
    struct IDisplay_vtbl *vtbl;
};
/* End of struct IDisplay Declaration */


/* Start of struct INetworkAdapter Declaration */
#  define INETWORKADAPTER_IID_STR "efa0f965-63c7-4c60-afdf-b1cc9943b9c0"
#  define INETWORKADAPTER_IID { \
    0xefa0f965, 0x63c7, 0x4c60, \
    { 0xaf, 0xdf, 0xb1, 0xcc, 0x99, 0x43, 0xb9, 0xc0 } \
}
struct INetworkAdapter_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetAdapterType)(INetworkAdapter *pThis, PRUint32 *adapterType);
    nsresult (*SetAdapterType)(INetworkAdapter *pThis, PRUint32 adapterType);

    nsresult (*GetSlot)(INetworkAdapter *pThis, PRUint32 *slot);

    nsresult (*GetEnabled)(INetworkAdapter *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(INetworkAdapter *pThis, PRBool enabled);

    nsresult (*GetMACAddress)(INetworkAdapter *pThis, PRUnichar * *MACAddress);
    nsresult (*SetMACAddress)(INetworkAdapter *pThis, PRUnichar * MACAddress);

    nsresult (*GetAttachmentType)(INetworkAdapter *pThis, PRUint32 *attachmentType);
    nsresult (*SetAttachmentType)(INetworkAdapter *pThis, PRUint32 attachmentType);

    nsresult (*GetBridgedInterface)(INetworkAdapter *pThis, PRUnichar * *bridgedInterface);
    nsresult (*SetBridgedInterface)(INetworkAdapter *pThis, PRUnichar * bridgedInterface);

    nsresult (*GetHostOnlyInterface)(INetworkAdapter *pThis, PRUnichar * *hostOnlyInterface);
    nsresult (*SetHostOnlyInterface)(INetworkAdapter *pThis, PRUnichar * hostOnlyInterface);

    nsresult (*GetInternalNetwork)(INetworkAdapter *pThis, PRUnichar * *internalNetwork);
    nsresult (*SetInternalNetwork)(INetworkAdapter *pThis, PRUnichar * internalNetwork);

    nsresult (*GetNATNetwork)(INetworkAdapter *pThis, PRUnichar * *NATNetwork);
    nsresult (*SetNATNetwork)(INetworkAdapter *pThis, PRUnichar * NATNetwork);

    nsresult (*GetGenericDriver)(INetworkAdapter *pThis, PRUnichar * *genericDriver);
    nsresult (*SetGenericDriver)(INetworkAdapter *pThis, PRUnichar * genericDriver);

    nsresult (*GetCableConnected)(INetworkAdapter *pThis, PRBool *cableConnected);
    nsresult (*SetCableConnected)(INetworkAdapter *pThis, PRBool cableConnected);

    nsresult (*GetLineSpeed)(INetworkAdapter *pThis, PRUint32 *lineSpeed);
    nsresult (*SetLineSpeed)(INetworkAdapter *pThis, PRUint32 lineSpeed);

    nsresult (*GetPromiscModePolicy)(INetworkAdapter *pThis, PRUint32 *promiscModePolicy);
    nsresult (*SetPromiscModePolicy)(INetworkAdapter *pThis, PRUint32 promiscModePolicy);

    nsresult (*GetTraceEnabled)(INetworkAdapter *pThis, PRBool *traceEnabled);
    nsresult (*SetTraceEnabled)(INetworkAdapter *pThis, PRBool traceEnabled);

    nsresult (*GetTraceFile)(INetworkAdapter *pThis, PRUnichar * *traceFile);
    nsresult (*SetTraceFile)(INetworkAdapter *pThis, PRUnichar * traceFile);

    nsresult (*GetNATEngine)(INetworkAdapter *pThis, INATEngine * *NATEngine);

    nsresult (*GetBootPriority)(INetworkAdapter *pThis, PRUint32 *bootPriority);
    nsresult (*SetBootPriority)(INetworkAdapter *pThis, PRUint32 bootPriority);

    nsresult (*GetBandwidthGroup)(INetworkAdapter *pThis, IBandwidthGroup * *bandwidthGroup);
    nsresult (*SetBandwidthGroup)(INetworkAdapter *pThis, IBandwidthGroup * bandwidthGroup);

    nsresult (*GetProperty)(
        INetworkAdapter *pThis,
        PRUnichar * key,
        PRUnichar * * value
    );

    nsresult (*SetProperty)(
        INetworkAdapter *pThis,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult (*GetProperties)(
        INetworkAdapter *pThis,
        PRUnichar * names,
        PRUint32 *returnNamesSize,
        PRUnichar *** returnNames,
        PRUint32 *returnValuesSize,
        PRUnichar *** returnValues
    );

};

struct INetworkAdapter
{
    struct INetworkAdapter_vtbl *vtbl;
};
/* End of struct INetworkAdapter Declaration */


/* Start of struct ISerialPort Declaration */
#  define ISERIALPORT_IID_STR "937f6970-5103-4745-b78e-d28dcf1479a8"
#  define ISERIALPORT_IID { \
    0x937f6970, 0x5103, 0x4745, \
    { 0xb7, 0x8e, 0xd2, 0x8d, 0xcf, 0x14, 0x79, 0xa8 } \
}
struct ISerialPort_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetSlot)(ISerialPort *pThis, PRUint32 *slot);

    nsresult (*GetEnabled)(ISerialPort *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(ISerialPort *pThis, PRBool enabled);

    nsresult (*GetIOBase)(ISerialPort *pThis, PRUint32 *IOBase);
    nsresult (*SetIOBase)(ISerialPort *pThis, PRUint32 IOBase);

    nsresult (*GetIRQ)(ISerialPort *pThis, PRUint32 *IRQ);
    nsresult (*SetIRQ)(ISerialPort *pThis, PRUint32 IRQ);

    nsresult (*GetHostMode)(ISerialPort *pThis, PRUint32 *hostMode);
    nsresult (*SetHostMode)(ISerialPort *pThis, PRUint32 hostMode);

    nsresult (*GetServer)(ISerialPort *pThis, PRBool *server);
    nsresult (*SetServer)(ISerialPort *pThis, PRBool server);

    nsresult (*GetPath)(ISerialPort *pThis, PRUnichar * *path);
    nsresult (*SetPath)(ISerialPort *pThis, PRUnichar * path);

};

struct ISerialPort
{
    struct ISerialPort_vtbl *vtbl;
};
/* End of struct ISerialPort Declaration */


/* Start of struct IParallelPort Declaration */
#  define IPARALLELPORT_IID_STR "0c925f06-dd10-4b77-8de8-294d738c3214"
#  define IPARALLELPORT_IID { \
    0x0c925f06, 0xdd10, 0x4b77, \
    { 0x8d, 0xe8, 0x29, 0x4d, 0x73, 0x8c, 0x32, 0x14 } \
}
struct IParallelPort_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetSlot)(IParallelPort *pThis, PRUint32 *slot);

    nsresult (*GetEnabled)(IParallelPort *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(IParallelPort *pThis, PRBool enabled);

    nsresult (*GetIOBase)(IParallelPort *pThis, PRUint32 *IOBase);
    nsresult (*SetIOBase)(IParallelPort *pThis, PRUint32 IOBase);

    nsresult (*GetIRQ)(IParallelPort *pThis, PRUint32 *IRQ);
    nsresult (*SetIRQ)(IParallelPort *pThis, PRUint32 IRQ);

    nsresult (*GetPath)(IParallelPort *pThis, PRUnichar * *path);
    nsresult (*SetPath)(IParallelPort *pThis, PRUnichar * path);

};

struct IParallelPort
{
    struct IParallelPort_vtbl *vtbl;
};
/* End of struct IParallelPort Declaration */


/* Start of struct IMachineDebugger Declaration */
#  define IMACHINEDEBUGGER_IID_STR "5e4534dc-21b8-4f6b-8a08-eef50e1a0aa1"
#  define IMACHINEDEBUGGER_IID { \
    0x5e4534dc, 0x21b8, 0x4f6b, \
    { 0x8a, 0x08, 0xee, 0xf5, 0x0e, 0x1a, 0x0a, 0xa1 } \
}
struct IMachineDebugger_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetSingleStep)(IMachineDebugger *pThis, PRBool *singleStep);
    nsresult (*SetSingleStep)(IMachineDebugger *pThis, PRBool singleStep);

    nsresult (*GetRecompileUser)(IMachineDebugger *pThis, PRBool *recompileUser);
    nsresult (*SetRecompileUser)(IMachineDebugger *pThis, PRBool recompileUser);

    nsresult (*GetRecompileSupervisor)(IMachineDebugger *pThis, PRBool *recompileSupervisor);
    nsresult (*SetRecompileSupervisor)(IMachineDebugger *pThis, PRBool recompileSupervisor);

    nsresult (*GetExecuteAllInIEM)(IMachineDebugger *pThis, PRBool *executeAllInIEM);
    nsresult (*SetExecuteAllInIEM)(IMachineDebugger *pThis, PRBool executeAllInIEM);

    nsresult (*GetPATMEnabled)(IMachineDebugger *pThis, PRBool *PATMEnabled);
    nsresult (*SetPATMEnabled)(IMachineDebugger *pThis, PRBool PATMEnabled);

    nsresult (*GetCSAMEnabled)(IMachineDebugger *pThis, PRBool *CSAMEnabled);
    nsresult (*SetCSAMEnabled)(IMachineDebugger *pThis, PRBool CSAMEnabled);

    nsresult (*GetLogEnabled)(IMachineDebugger *pThis, PRBool *logEnabled);
    nsresult (*SetLogEnabled)(IMachineDebugger *pThis, PRBool logEnabled);

    nsresult (*GetLogDbgFlags)(IMachineDebugger *pThis, PRUnichar * *logDbgFlags);

    nsresult (*GetLogDbgGroups)(IMachineDebugger *pThis, PRUnichar * *logDbgGroups);

    nsresult (*GetLogDbgDestinations)(IMachineDebugger *pThis, PRUnichar * *logDbgDestinations);

    nsresult (*GetLogRelFlags)(IMachineDebugger *pThis, PRUnichar * *logRelFlags);

    nsresult (*GetLogRelGroups)(IMachineDebugger *pThis, PRUnichar * *logRelGroups);

    nsresult (*GetLogRelDestinations)(IMachineDebugger *pThis, PRUnichar * *logRelDestinations);

    nsresult (*GetHWVirtExEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExEnabled);

    nsresult (*GetHWVirtExNestedPagingEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExNestedPagingEnabled);

    nsresult (*GetHWVirtExVPIDEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExVPIDEnabled);

    nsresult (*GetHWVirtExUXEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExUXEnabled);

    nsresult (*GetOSName)(IMachineDebugger *pThis, PRUnichar * *OSName);

    nsresult (*GetOSVersion)(IMachineDebugger *pThis, PRUnichar * *OSVersion);

    nsresult (*GetPAEEnabled)(IMachineDebugger *pThis, PRBool *PAEEnabled);

    nsresult (*GetVirtualTimeRate)(IMachineDebugger *pThis, PRUint32 *virtualTimeRate);
    nsresult (*SetVirtualTimeRate)(IMachineDebugger *pThis, PRUint32 virtualTimeRate);

    nsresult (*GetVM)(IMachineDebugger *pThis, PRInt64 *VM);

    nsresult (*DumpGuestCore)(
        IMachineDebugger *pThis,
        PRUnichar * filename,
        PRUnichar * compression
    );

    nsresult (*DumpHostProcessCore)(
        IMachineDebugger *pThis,
        PRUnichar * filename,
        PRUnichar * compression
    );

    nsresult (*Info)(
        IMachineDebugger *pThis,
        PRUnichar * name,
        PRUnichar * args,
        PRUnichar * * info
    );

    nsresult (*InjectNMI)(IMachineDebugger *pThis );

    nsresult (*ModifyLogGroups)(
        IMachineDebugger *pThis,
        PRUnichar * settings
    );

    nsresult (*ModifyLogFlags)(
        IMachineDebugger *pThis,
        PRUnichar * settings
    );

    nsresult (*ModifyLogDestinations)(
        IMachineDebugger *pThis,
        PRUnichar * settings
    );

    nsresult (*ReadPhysicalMemory)(
        IMachineDebugger *pThis,
        PRInt64 address,
        PRUint32 size,
        PRUint32 *bytesSize,
        PRUint8** bytes
    );

    nsresult (*WritePhysicalMemory)(
        IMachineDebugger *pThis,
        PRInt64 address,
        PRUint32 size,
        PRUint32 bytesSize,
        PRUint8* bytes
    );

    nsresult (*ReadVirtualMemory)(
        IMachineDebugger *pThis,
        PRUint32 cpuId,
        PRInt64 address,
        PRUint32 size,
        PRUint32 *bytesSize,
        PRUint8** bytes
    );

    nsresult (*WriteVirtualMemory)(
        IMachineDebugger *pThis,
        PRUint32 cpuId,
        PRInt64 address,
        PRUint32 size,
        PRUint32 bytesSize,
        PRUint8* bytes
    );

    nsresult (*DetectOS)(
        IMachineDebugger *pThis,
        PRUnichar * * os
    );

    nsresult (*GetRegister)(
        IMachineDebugger *pThis,
        PRUint32 cpuId,
        PRUnichar * name,
        PRUnichar * * value
    );

    nsresult (*GetRegisters)(
        IMachineDebugger *pThis,
        PRUint32 cpuId,
        PRUint32 *namesSize,
        PRUnichar *** names,
        PRUint32 *valuesSize,
        PRUnichar *** values
    );

    nsresult (*SetRegister)(
        IMachineDebugger *pThis,
        PRUint32 cpuId,
        PRUnichar * name,
        PRUnichar * value
    );

    nsresult (*SetRegisters)(
        IMachineDebugger *pThis,
        PRUint32 cpuId,
        PRUint32 namesSize,
        PRUnichar ** names,
        PRUint32 valuesSize,
        PRUnichar ** values
    );

    nsresult (*DumpGuestStack)(
        IMachineDebugger *pThis,
        PRUint32 cpuId,
        PRUnichar * * stack
    );

    nsresult (*ResetStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern
    );

    nsresult (*DumpStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern
    );

    nsresult (*GetStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern,
        PRBool withDescriptions,
        PRUnichar * * stats
    );

};

struct IMachineDebugger
{
    struct IMachineDebugger_vtbl *vtbl;
};
/* End of struct IMachineDebugger Declaration */


/* Start of struct IUSBDeviceFilters Declaration */
#  define IUSBDEVICEFILTERS_IID_STR "2ab550b2-53cc-4c2e-ae07-0adf4114e75c"
#  define IUSBDEVICEFILTERS_IID { \
    0x2ab550b2, 0x53cc, 0x4c2e, \
    { 0xae, 0x07, 0x0a, 0xdf, 0x41, 0x14, 0xe7, 0x5c } \
}
struct IUSBDeviceFilters_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetDeviceFilters)(IUSBDeviceFilters *pThis, PRUint32 *deviceFiltersSize, IUSBDeviceFilter * **deviceFilters);

    nsresult (*CreateDeviceFilter)(
        IUSBDeviceFilters *pThis,
        PRUnichar * name,
        IUSBDeviceFilter * * filter
    );

    nsresult (*InsertDeviceFilter)(
        IUSBDeviceFilters *pThis,
        PRUint32 position,
        IUSBDeviceFilter * filter
    );

    nsresult (*RemoveDeviceFilter)(
        IUSBDeviceFilters *pThis,
        PRUint32 position,
        IUSBDeviceFilter * * filter
    );

};

struct IUSBDeviceFilters
{
    struct IUSBDeviceFilters_vtbl *vtbl;
};
/* End of struct IUSBDeviceFilters Declaration */


/* Start of struct IUSBController Declaration */
#  define IUSBCONTROLLER_IID_STR "d2745291-65f7-4d75-9556-38047d802319"
#  define IUSBCONTROLLER_IID { \
    0xd2745291, 0x65f7, 0x4d75, \
    { 0x95, 0x56, 0x38, 0x04, 0x7d, 0x80, 0x23, 0x19 } \
}
struct IUSBController_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IUSBController *pThis, PRUnichar * *name);

    nsresult (*GetType)(IUSBController *pThis, PRUint32 *type);

    nsresult (*GetUSBStandard)(IUSBController *pThis, PRUint16 *USBStandard);

};

struct IUSBController
{
    struct IUSBController_vtbl *vtbl;
};
/* End of struct IUSBController Declaration */


/* Start of struct IUSBDevice Declaration */
#  define IUSBDEVICE_IID_STR "f8967b0b-4483-400f-92b5-8b675d98a85b"
#  define IUSBDEVICE_IID { \
    0xf8967b0b, 0x4483, 0x400f, \
    { 0x92, 0xb5, 0x8b, 0x67, 0x5d, 0x98, 0xa8, 0x5b } \
}
struct IUSBDevice_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetId)(IUSBDevice *pThis, PRUnichar * *id);

    nsresult (*GetVendorId)(IUSBDevice *pThis, PRUint16 *vendorId);

    nsresult (*GetProductId)(IUSBDevice *pThis, PRUint16 *productId);

    nsresult (*GetRevision)(IUSBDevice *pThis, PRUint16 *revision);

    nsresult (*GetManufacturer)(IUSBDevice *pThis, PRUnichar * *manufacturer);

    nsresult (*GetProduct)(IUSBDevice *pThis, PRUnichar * *product);

    nsresult (*GetSerialNumber)(IUSBDevice *pThis, PRUnichar * *serialNumber);

    nsresult (*GetAddress)(IUSBDevice *pThis, PRUnichar * *address);

    nsresult (*GetPort)(IUSBDevice *pThis, PRUint16 *port);

    nsresult (*GetVersion)(IUSBDevice *pThis, PRUint16 *version);

    nsresult (*GetPortVersion)(IUSBDevice *pThis, PRUint16 *portVersion);

    nsresult (*GetRemote)(IUSBDevice *pThis, PRBool *remote);

};

struct IUSBDevice
{
    struct IUSBDevice_vtbl *vtbl;
};
/* End of struct IUSBDevice Declaration */


/* Start of struct IUSBDeviceFilter Declaration */
#  define IUSBDEVICEFILTER_IID_STR "d6831fb4-1a94-4c2c-96ef-8d0d6192066d"
#  define IUSBDEVICEFILTER_IID { \
    0xd6831fb4, 0x1a94, 0x4c2c, \
    { 0x96, 0xef, 0x8d, 0x0d, 0x61, 0x92, 0x06, 0x6d } \
}
struct IUSBDeviceFilter_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IUSBDeviceFilter *pThis, PRUnichar * *name);
    nsresult (*SetName)(IUSBDeviceFilter *pThis, PRUnichar * name);

    nsresult (*GetActive)(IUSBDeviceFilter *pThis, PRBool *active);
    nsresult (*SetActive)(IUSBDeviceFilter *pThis, PRBool active);

    nsresult (*GetVendorId)(IUSBDeviceFilter *pThis, PRUnichar * *vendorId);
    nsresult (*SetVendorId)(IUSBDeviceFilter *pThis, PRUnichar * vendorId);

    nsresult (*GetProductId)(IUSBDeviceFilter *pThis, PRUnichar * *productId);
    nsresult (*SetProductId)(IUSBDeviceFilter *pThis, PRUnichar * productId);

    nsresult (*GetRevision)(IUSBDeviceFilter *pThis, PRUnichar * *revision);
    nsresult (*SetRevision)(IUSBDeviceFilter *pThis, PRUnichar * revision);

    nsresult (*GetManufacturer)(IUSBDeviceFilter *pThis, PRUnichar * *manufacturer);
    nsresult (*SetManufacturer)(IUSBDeviceFilter *pThis, PRUnichar * manufacturer);

    nsresult (*GetProduct)(IUSBDeviceFilter *pThis, PRUnichar * *product);
    nsresult (*SetProduct)(IUSBDeviceFilter *pThis, PRUnichar * product);

    nsresult (*GetSerialNumber)(IUSBDeviceFilter *pThis, PRUnichar * *serialNumber);
    nsresult (*SetSerialNumber)(IUSBDeviceFilter *pThis, PRUnichar * serialNumber);

    nsresult (*GetPort)(IUSBDeviceFilter *pThis, PRUnichar * *port);
    nsresult (*SetPort)(IUSBDeviceFilter *pThis, PRUnichar * port);

    nsresult (*GetRemote)(IUSBDeviceFilter *pThis, PRUnichar * *remote);
    nsresult (*SetRemote)(IUSBDeviceFilter *pThis, PRUnichar * remote);

    nsresult (*GetMaskedInterfaces)(IUSBDeviceFilter *pThis, PRUint32 *maskedInterfaces);
    nsresult (*SetMaskedInterfaces)(IUSBDeviceFilter *pThis, PRUint32 maskedInterfaces);

};

struct IUSBDeviceFilter
{
    struct IUSBDeviceFilter_vtbl *vtbl;
};
/* End of struct IUSBDeviceFilter Declaration */


/* Start of struct IHostUSBDevice Declaration */
#  define IHOSTUSBDEVICE_IID_STR "173b4b44-d268-4334-a00d-b6521c9a740a"
#  define IHOSTUSBDEVICE_IID { \
    0x173b4b44, 0xd268, 0x4334, \
    { 0xa0, 0x0d, 0xb6, 0x52, 0x1c, 0x9a, 0x74, 0x0a } \
}
struct IHostUSBDevice_vtbl
{
    struct IUSBDevice_vtbl iusbdevice;

    nsresult (*GetState)(IHostUSBDevice *pThis, PRUint32 *state);

};

struct IHostUSBDevice
{
    struct IHostUSBDevice_vtbl *vtbl;
};
/* End of struct IHostUSBDevice Declaration */


/* Start of struct IHostUSBDeviceFilter Declaration */
#  define IHOSTUSBDEVICEFILTER_IID_STR "4cc70246-d74a-400f-8222-3900489c0374"
#  define IHOSTUSBDEVICEFILTER_IID { \
    0x4cc70246, 0xd74a, 0x400f, \
    { 0x82, 0x22, 0x39, 0x00, 0x48, 0x9c, 0x03, 0x74 } \
}
struct IHostUSBDeviceFilter_vtbl
{
    struct IUSBDeviceFilter_vtbl iusbdevicefilter;

    nsresult (*GetAction)(IHostUSBDeviceFilter *pThis, PRUint32 *action);
    nsresult (*SetAction)(IHostUSBDeviceFilter *pThis, PRUint32 action);

};

struct IHostUSBDeviceFilter
{
    struct IHostUSBDeviceFilter_vtbl *vtbl;
};
/* End of struct IHostUSBDeviceFilter Declaration */


/* Start of struct IAudioAdapter Declaration */
#  define IAUDIOADAPTER_IID_STR "921873db-5f3f-4b69-91f9-7be9e535a2cb"
#  define IAUDIOADAPTER_IID { \
    0x921873db, 0x5f3f, 0x4b69, \
    { 0x91, 0xf9, 0x7b, 0xe9, 0xe5, 0x35, 0xa2, 0xcb } \
}
struct IAudioAdapter_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetEnabled)(IAudioAdapter *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(IAudioAdapter *pThis, PRBool enabled);

    nsresult (*GetAudioController)(IAudioAdapter *pThis, PRUint32 *audioController);
    nsresult (*SetAudioController)(IAudioAdapter *pThis, PRUint32 audioController);

    nsresult (*GetAudioDriver)(IAudioAdapter *pThis, PRUint32 *audioDriver);
    nsresult (*SetAudioDriver)(IAudioAdapter *pThis, PRUint32 audioDriver);

};

struct IAudioAdapter
{
    struct IAudioAdapter_vtbl *vtbl;
};
/* End of struct IAudioAdapter Declaration */


/* Start of struct IVRDEServer Declaration */
#  define IVRDESERVER_IID_STR "d38de40a-c2c1-4e95-b5a4-167b05f5694c"
#  define IVRDESERVER_IID { \
    0xd38de40a, 0xc2c1, 0x4e95, \
    { 0xb5, 0xa4, 0x16, 0x7b, 0x05, 0xf5, 0x69, 0x4c } \
}
struct IVRDEServer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetEnabled)(IVRDEServer *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(IVRDEServer *pThis, PRBool enabled);

    nsresult (*GetAuthType)(IVRDEServer *pThis, PRUint32 *authType);
    nsresult (*SetAuthType)(IVRDEServer *pThis, PRUint32 authType);

    nsresult (*GetAuthTimeout)(IVRDEServer *pThis, PRUint32 *authTimeout);
    nsresult (*SetAuthTimeout)(IVRDEServer *pThis, PRUint32 authTimeout);

    nsresult (*GetAllowMultiConnection)(IVRDEServer *pThis, PRBool *allowMultiConnection);
    nsresult (*SetAllowMultiConnection)(IVRDEServer *pThis, PRBool allowMultiConnection);

    nsresult (*GetReuseSingleConnection)(IVRDEServer *pThis, PRBool *reuseSingleConnection);
    nsresult (*SetReuseSingleConnection)(IVRDEServer *pThis, PRBool reuseSingleConnection);

    nsresult (*GetVRDEExtPack)(IVRDEServer *pThis, PRUnichar * *VRDEExtPack);
    nsresult (*SetVRDEExtPack)(IVRDEServer *pThis, PRUnichar * VRDEExtPack);

    nsresult (*GetAuthLibrary)(IVRDEServer *pThis, PRUnichar * *authLibrary);
    nsresult (*SetAuthLibrary)(IVRDEServer *pThis, PRUnichar * authLibrary);

    nsresult (*GetVRDEProperties)(IVRDEServer *pThis, PRUint32 *VRDEPropertiesSize, PRUnichar * **VRDEProperties);

    nsresult (*SetVRDEProperty)(
        IVRDEServer *pThis,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult (*GetVRDEProperty)(
        IVRDEServer *pThis,
        PRUnichar * key,
        PRUnichar * * value
    );

};

struct IVRDEServer
{
    struct IVRDEServer_vtbl *vtbl;
};
/* End of struct IVRDEServer Declaration */


/* Start of struct ISharedFolder Declaration */
#  define ISHAREDFOLDER_IID_STR "8388da11-b559-4574-a5b7-2bd7acd5cef8"
#  define ISHAREDFOLDER_IID { \
    0x8388da11, 0xb559, 0x4574, \
    { 0xa5, 0xb7, 0x2b, 0xd7, 0xac, 0xd5, 0xce, 0xf8 } \
}
struct ISharedFolder_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(ISharedFolder *pThis, PRUnichar * *name);

    nsresult (*GetHostPath)(ISharedFolder *pThis, PRUnichar * *hostPath);

    nsresult (*GetAccessible)(ISharedFolder *pThis, PRBool *accessible);

    nsresult (*GetWritable)(ISharedFolder *pThis, PRBool *writable);

    nsresult (*GetAutoMount)(ISharedFolder *pThis, PRBool *autoMount);

    nsresult (*GetLastAccessError)(ISharedFolder *pThis, PRUnichar * *lastAccessError);

};

struct ISharedFolder
{
    struct ISharedFolder_vtbl *vtbl;
};
/* End of struct ISharedFolder Declaration */


/* Start of struct IInternalSessionControl Declaration */
#  define IINTERNALSESSIONCONTROL_IID_STR "2d2124a7-0f62-4907-ae21-eee5a559bdde"
#  define IINTERNALSESSIONCONTROL_IID { \
    0x2d2124a7, 0x0f62, 0x4907, \
    { 0xae, 0x21, 0xee, 0xe5, 0xa5, 0x59, 0xbd, 0xde } \
}
struct IInternalSessionControl_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetPID)(
        IInternalSessionControl *pThis,
        PRUint32 * pid
    );

    nsresult (*GetRemoteConsole)(
        IInternalSessionControl *pThis,
        IConsole * * console
    );

    nsresult (*AssignRemoteMachine)(
        IInternalSessionControl *pThis,
        IMachine * machine,
        IConsole * console
    );

    nsresult (*UpdateMachineState)(
        IInternalSessionControl *pThis,
        PRUint32 machineState
    );

    nsresult (*Uninitialize)(IInternalSessionControl *pThis );

    nsresult (*OnNetworkAdapterChange)(
        IInternalSessionControl *pThis,
        INetworkAdapter * networkAdapter,
        PRBool changeAdapter
    );

    nsresult (*OnSerialPortChange)(
        IInternalSessionControl *pThis,
        ISerialPort * serialPort
    );

    nsresult (*OnParallelPortChange)(
        IInternalSessionControl *pThis,
        IParallelPort * parallelPort
    );

    nsresult (*OnStorageControllerChange)(IInternalSessionControl *pThis );

    nsresult (*OnMediumChange)(
        IInternalSessionControl *pThis,
        IMediumAttachment * mediumAttachment,
        PRBool force
    );

    nsresult (*OnStorageDeviceChange)(
        IInternalSessionControl *pThis,
        IMediumAttachment * mediumAttachment,
        PRBool remove,
        PRBool silent
    );

    nsresult (*OnClipboardModeChange)(
        IInternalSessionControl *pThis,
        PRUint32 clipboardMode
    );

    nsresult (*OnDragAndDropModeChange)(
        IInternalSessionControl *pThis,
        PRUint32 dragAndDropMode
    );

    nsresult (*OnCPUChange)(
        IInternalSessionControl *pThis,
        PRUint32 cpu,
        PRBool add
    );

    nsresult (*OnCPUExecutionCapChange)(
        IInternalSessionControl *pThis,
        PRUint32 executionCap
    );

    nsresult (*OnVRDEServerChange)(
        IInternalSessionControl *pThis,
        PRBool restart
    );

    nsresult (*OnVideoCaptureChange)(IInternalSessionControl *pThis );

    nsresult (*OnUSBControllerChange)(IInternalSessionControl *pThis );

    nsresult (*OnSharedFolderChange)(
        IInternalSessionControl *pThis,
        PRBool global
    );

    nsresult (*OnUSBDeviceAttach)(
        IInternalSessionControl *pThis,
        IUSBDevice * device,
        IVirtualBoxErrorInfo * error,
        PRUint32 maskedInterfaces
    );

    nsresult (*OnUSBDeviceDetach)(
        IInternalSessionControl *pThis,
        PRUnichar * id,
        IVirtualBoxErrorInfo * error
    );

    nsresult (*OnShowWindow)(
        IInternalSessionControl *pThis,
        PRBool check,
        PRBool * canShow,
        PRInt64 * winId
    );

    nsresult (*OnBandwidthGroupChange)(
        IInternalSessionControl *pThis,
        IBandwidthGroup * bandwidthGroup
    );

    nsresult (*AccessGuestProperty)(
        IInternalSessionControl *pThis,
        PRUnichar * name,
        PRUnichar * value,
        PRUnichar * flags,
        PRBool isSetter,
        PRUnichar * * retValue,
        PRInt64 * retTimestamp,
        PRUnichar * * retFlags
    );

    nsresult (*EnumerateGuestProperties)(
        IInternalSessionControl *pThis,
        PRUnichar * patterns,
        PRUint32 *keysSize,
        PRUnichar *** keys,
        PRUint32 *valuesSize,
        PRUnichar *** values,
        PRUint32 *timestampsSize,
        PRInt64** timestamps,
        PRUint32 *flagsSize,
        PRUnichar *** flags
    );

    nsresult (*OnlineMergeMedium)(
        IInternalSessionControl *pThis,
        IMediumAttachment * mediumAttachment,
        PRUint32 sourceIdx,
        PRUint32 targetIdx,
        IProgress * progress
    );

    nsresult (*EnableVMMStatistics)(
        IInternalSessionControl *pThis,
        PRBool enable
    );

    nsresult (*PauseWithReason)(
        IInternalSessionControl *pThis,
        PRUint32 reason
    );

    nsresult (*ResumeWithReason)(
        IInternalSessionControl *pThis,
        PRUint32 reason
    );

    nsresult (*SaveStateWithReason)(
        IInternalSessionControl *pThis,
        PRUint32 reason,
        IProgress * * progress
    );

};

struct IInternalSessionControl
{
    struct IInternalSessionControl_vtbl *vtbl;
};
/* End of struct IInternalSessionControl Declaration */


/* Start of struct ISession Declaration */
#  define ISESSION_IID_STR "12F4DCDB-12B2-4EC1-B7CD-DDD9F6C5BF4D"
#  define ISESSION_IID { \
    0x12F4DCDB, 0x12B2, 0x4EC1, \
    { 0xB7, 0xCD, 0xDD, 0xD9, 0xF6, 0xC5, 0xBF, 0x4D } \
}
struct ISession_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetState)(ISession *pThis, PRUint32 *state);

    nsresult (*GetType)(ISession *pThis, PRUint32 *type);

    nsresult (*GetMachine)(ISession *pThis, IMachine * *machine);

    nsresult (*GetConsole)(ISession *pThis, IConsole * *console);

    nsresult (*UnlockMachine)(ISession *pThis );

};

struct ISession
{
    struct ISession_vtbl *vtbl;
};
/* End of struct ISession Declaration */


/* Start of struct IStorageController Declaration */
#  define ISTORAGECONTROLLER_IID_STR "a1556333-09b6-46d9-bfb7-fc239b7fbe1e"
#  define ISTORAGECONTROLLER_IID { \
    0xa1556333, 0x09b6, 0x46d9, \
    { 0xbf, 0xb7, 0xfc, 0x23, 0x9b, 0x7f, 0xbe, 0x1e } \
}
struct IStorageController_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IStorageController *pThis, PRUnichar * *name);

    nsresult (*GetMaxDevicesPerPortCount)(IStorageController *pThis, PRUint32 *maxDevicesPerPortCount);

    nsresult (*GetMinPortCount)(IStorageController *pThis, PRUint32 *minPortCount);

    nsresult (*GetMaxPortCount)(IStorageController *pThis, PRUint32 *maxPortCount);

    nsresult (*GetInstance)(IStorageController *pThis, PRUint32 *instance);
    nsresult (*SetInstance)(IStorageController *pThis, PRUint32 instance);

    nsresult (*GetPortCount)(IStorageController *pThis, PRUint32 *portCount);
    nsresult (*SetPortCount)(IStorageController *pThis, PRUint32 portCount);

    nsresult (*GetBus)(IStorageController *pThis, PRUint32 *bus);

    nsresult (*GetControllerType)(IStorageController *pThis, PRUint32 *controllerType);
    nsresult (*SetControllerType)(IStorageController *pThis, PRUint32 controllerType);

    nsresult (*GetUseHostIOCache)(IStorageController *pThis, PRBool *useHostIOCache);
    nsresult (*SetUseHostIOCache)(IStorageController *pThis, PRBool useHostIOCache);

    nsresult (*GetBootable)(IStorageController *pThis, PRBool *bootable);

};

struct IStorageController
{
    struct IStorageController_vtbl *vtbl;
};
/* End of struct IStorageController Declaration */


/* Start of struct IPerformanceMetric Declaration */
#  define IPERFORMANCEMETRIC_IID_STR "2a1a60ae-9345-4019-ad53-d34ba41cbfe9"
#  define IPERFORMANCEMETRIC_IID { \
    0x2a1a60ae, 0x9345, 0x4019, \
    { 0xad, 0x53, 0xd3, 0x4b, 0xa4, 0x1c, 0xbf, 0xe9 } \
}
struct IPerformanceMetric_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetMetricName)(IPerformanceMetric *pThis, PRUnichar * *metricName);

    nsresult (*GetObject)(IPerformanceMetric *pThis, nsISupports * *object);

    nsresult (*GetDescription)(IPerformanceMetric *pThis, PRUnichar * *description);

    nsresult (*GetPeriod)(IPerformanceMetric *pThis, PRUint32 *period);

    nsresult (*GetCount)(IPerformanceMetric *pThis, PRUint32 *count);

    nsresult (*GetUnit)(IPerformanceMetric *pThis, PRUnichar * *unit);

    nsresult (*GetMinimumValue)(IPerformanceMetric *pThis, PRInt32 *minimumValue);

    nsresult (*GetMaximumValue)(IPerformanceMetric *pThis, PRInt32 *maximumValue);

};

struct IPerformanceMetric
{
    struct IPerformanceMetric_vtbl *vtbl;
};
/* End of struct IPerformanceMetric Declaration */


/* Start of struct IPerformanceCollector Declaration */
#  define IPERFORMANCECOLLECTOR_IID_STR "e22e1acb-ac4a-43bb-a31c-17321659b0c6"
#  define IPERFORMANCECOLLECTOR_IID { \
    0xe22e1acb, 0xac4a, 0x43bb, \
    { 0xa3, 0x1c, 0x17, 0x32, 0x16, 0x59, 0xb0, 0xc6 } \
}
struct IPerformanceCollector_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetMetricNames)(IPerformanceCollector *pThis, PRUint32 *metricNamesSize, PRUnichar * **metricNames);

    nsresult (*GetMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *metricsSize,
        IPerformanceMetric *** metrics
    );

    nsresult (*SetupMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 period,
        PRUint32 count,
        PRUint32 *affectedMetricsSize,
        IPerformanceMetric *** affectedMetrics
    );

    nsresult (*EnableMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *affectedMetricsSize,
        IPerformanceMetric *** affectedMetrics
    );

    nsresult (*DisableMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *affectedMetricsSize,
        IPerformanceMetric *** affectedMetrics
    );

    nsresult (*QueryMetricsData)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *returnMetricNamesSize,
        PRUnichar *** returnMetricNames,
        PRUint32 *returnObjectsSize,
        nsISupports *** returnObjects,
        PRUint32 *returnUnitsSize,
        PRUnichar *** returnUnits,
        PRUint32 *returnScalesSize,
        PRUint32** returnScales,
        PRUint32 *returnSequenceNumbersSize,
        PRUint32** returnSequenceNumbers,
        PRUint32 *returnDataIndicesSize,
        PRUint32** returnDataIndices,
        PRUint32 *returnDataLengthsSize,
        PRUint32** returnDataLengths,
        PRUint32 *returnDataSize,
        PRInt32** returnData
    );

};

struct IPerformanceCollector
{
    struct IPerformanceCollector_vtbl *vtbl;
};
/* End of struct IPerformanceCollector Declaration */


/* Start of struct INATEngine Declaration */
#  define INATENGINE_IID_STR "26451b99-3b2d-4dcb-8e4b-d63654218175"
#  define INATENGINE_IID { \
    0x26451b99, 0x3b2d, 0x4dcb, \
    { 0x8e, 0x4b, 0xd6, 0x36, 0x54, 0x21, 0x81, 0x75 } \
}
struct INATEngine_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetNetwork)(INATEngine *pThis, PRUnichar * *network);
    nsresult (*SetNetwork)(INATEngine *pThis, PRUnichar * network);

    nsresult (*GetHostIP)(INATEngine *pThis, PRUnichar * *hostIP);
    nsresult (*SetHostIP)(INATEngine *pThis, PRUnichar * hostIP);

    nsresult (*GetTFTPPrefix)(INATEngine *pThis, PRUnichar * *TFTPPrefix);
    nsresult (*SetTFTPPrefix)(INATEngine *pThis, PRUnichar * TFTPPrefix);

    nsresult (*GetTFTPBootFile)(INATEngine *pThis, PRUnichar * *TFTPBootFile);
    nsresult (*SetTFTPBootFile)(INATEngine *pThis, PRUnichar * TFTPBootFile);

    nsresult (*GetTFTPNextServer)(INATEngine *pThis, PRUnichar * *TFTPNextServer);
    nsresult (*SetTFTPNextServer)(INATEngine *pThis, PRUnichar * TFTPNextServer);

    nsresult (*GetAliasMode)(INATEngine *pThis, PRUint32 *aliasMode);
    nsresult (*SetAliasMode)(INATEngine *pThis, PRUint32 aliasMode);

    nsresult (*GetDNSPassDomain)(INATEngine *pThis, PRBool *DNSPassDomain);
    nsresult (*SetDNSPassDomain)(INATEngine *pThis, PRBool DNSPassDomain);

    nsresult (*GetDNSProxy)(INATEngine *pThis, PRBool *DNSProxy);
    nsresult (*SetDNSProxy)(INATEngine *pThis, PRBool DNSProxy);

    nsresult (*GetDNSUseHostResolver)(INATEngine *pThis, PRBool *DNSUseHostResolver);
    nsresult (*SetDNSUseHostResolver)(INATEngine *pThis, PRBool DNSUseHostResolver);

    nsresult (*GetRedirects)(INATEngine *pThis, PRUint32 *redirectsSize, PRUnichar * **redirects);

    nsresult (*SetNetworkSettings)(
        INATEngine *pThis,
        PRUint32 mtu,
        PRUint32 sockSnd,
        PRUint32 sockRcv,
        PRUint32 TcpWndSnd,
        PRUint32 TcpWndRcv
    );

    nsresult (*GetNetworkSettings)(
        INATEngine *pThis,
        PRUint32 * mtu,
        PRUint32 * sockSnd,
        PRUint32 * sockRcv,
        PRUint32 * TcpWndSnd,
        PRUint32 * TcpWndRcv
    );

    nsresult (*AddRedirect)(
        INATEngine *pThis,
        PRUnichar * name,
        PRUint32 proto,
        PRUnichar * hostIP,
        PRUint16 hostPort,
        PRUnichar * guestIP,
        PRUint16 guestPort
    );

    nsresult (*RemoveRedirect)(
        INATEngine *pThis,
        PRUnichar * name
    );

};

struct INATEngine
{
    struct INATEngine_vtbl *vtbl;
};
/* End of struct INATEngine Declaration */


/* Start of struct IExtPackPlugIn Declaration */
#  define IEXTPACKPLUGIN_IID_STR "58000040-e718-4746-bbce-4b86d96da461"
#  define IEXTPACKPLUGIN_IID { \
    0x58000040, 0xe718, 0x4746, \
    { 0xbb, 0xce, 0x4b, 0x86, 0xd9, 0x6d, 0xa4, 0x61 } \
}
struct IExtPackPlugIn_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IExtPackPlugIn *pThis, PRUnichar * *name);

    nsresult (*GetDescription)(IExtPackPlugIn *pThis, PRUnichar * *description);

    nsresult (*GetFrontend)(IExtPackPlugIn *pThis, PRUnichar * *frontend);

    nsresult (*GetModulePath)(IExtPackPlugIn *pThis, PRUnichar * *modulePath);

};

struct IExtPackPlugIn
{
    struct IExtPackPlugIn_vtbl *vtbl;
};
/* End of struct IExtPackPlugIn Declaration */


/* Start of struct IExtPackBase Declaration */
#  define IEXTPACKBASE_IID_STR "f79b75d8-2890-4f34-ffff-ffffa144e82c"
#  define IEXTPACKBASE_IID { \
    0xf79b75d8, 0x2890, 0x4f34, \
    { 0xff, 0xff, 0xff, 0xff, 0xa1, 0x44, 0xe8, 0x2c } \
}
struct IExtPackBase_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IExtPackBase *pThis, PRUnichar * *name);

    nsresult (*GetDescription)(IExtPackBase *pThis, PRUnichar * *description);

    nsresult (*GetVersion)(IExtPackBase *pThis, PRUnichar * *version);

    nsresult (*GetRevision)(IExtPackBase *pThis, PRUint32 *revision);

    nsresult (*GetEdition)(IExtPackBase *pThis, PRUnichar * *edition);

    nsresult (*GetVRDEModule)(IExtPackBase *pThis, PRUnichar * *VRDEModule);

    nsresult (*GetPlugIns)(IExtPackBase *pThis, PRUint32 *plugInsSize, IExtPackPlugIn * **plugIns);

    nsresult (*GetUsable)(IExtPackBase *pThis, PRBool *usable);

    nsresult (*GetWhyUnusable)(IExtPackBase *pThis, PRUnichar * *whyUnusable);

    nsresult (*GetShowLicense)(IExtPackBase *pThis, PRBool *showLicense);

    nsresult (*GetLicense)(IExtPackBase *pThis, PRUnichar * *license);

    nsresult (*QueryLicense)(
        IExtPackBase *pThis,
        PRUnichar * preferredLocale,
        PRUnichar * preferredLanguage,
        PRUnichar * format,
        PRUnichar * * licenseText
    );

};

struct IExtPackBase
{
    struct IExtPackBase_vtbl *vtbl;
};
/* End of struct IExtPackBase Declaration */


/* Start of struct IExtPack Declaration */
#  define IEXTPACK_IID_STR "431685da-3618-4ebc-b038-833ba829b4b2"
#  define IEXTPACK_IID { \
    0x431685da, 0x3618, 0x4ebc, \
    { 0xb0, 0x38, 0x83, 0x3b, 0xa8, 0x29, 0xb4, 0xb2 } \
}
struct IExtPack_vtbl
{
    struct IExtPackBase_vtbl iextpackbase;

    nsresult (*QueryObject)(
        IExtPack *pThis,
        PRUnichar * objUuid,
        nsISupports * * returnInterface
    );

};

struct IExtPack
{
    struct IExtPack_vtbl *vtbl;
};
/* End of struct IExtPack Declaration */


/* Start of struct IExtPackFile Declaration */
#  define IEXTPACKFILE_IID_STR "b6b49f55-efcc-4f08-b486-56e8d8afb10b"
#  define IEXTPACKFILE_IID { \
    0xb6b49f55, 0xefcc, 0x4f08, \
    { 0xb4, 0x86, 0x56, 0xe8, 0xd8, 0xaf, 0xb1, 0x0b } \
}
struct IExtPackFile_vtbl
{
    struct IExtPackBase_vtbl iextpackbase;

    nsresult (*GetFilePath)(IExtPackFile *pThis, PRUnichar * *filePath);

    nsresult (*Install)(
        IExtPackFile *pThis,
        PRBool replace,
        PRUnichar * displayInfo,
        IProgress * * progess
    );

};

struct IExtPackFile
{
    struct IExtPackFile_vtbl *vtbl;
};
/* End of struct IExtPackFile Declaration */


/* Start of struct IExtPackManager Declaration */
#  define IEXTPACKMANAGER_IID_STR "3295e6ce-b051-47b2-9514-2c588bfe7554"
#  define IEXTPACKMANAGER_IID { \
    0x3295e6ce, 0xb051, 0x47b2, \
    { 0x95, 0x14, 0x2c, 0x58, 0x8b, 0xfe, 0x75, 0x54 } \
}
struct IExtPackManager_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetInstalledExtPacks)(IExtPackManager *pThis, PRUint32 *installedExtPacksSize, IExtPack * **installedExtPacks);

    nsresult (*Find)(
        IExtPackManager *pThis,
        PRUnichar * name,
        IExtPack * * returnData
    );

    nsresult (*OpenExtPackFile)(
        IExtPackManager *pThis,
        PRUnichar * path,
        IExtPackFile * * file
    );

    nsresult (*Uninstall)(
        IExtPackManager *pThis,
        PRUnichar * name,
        PRBool forcedRemoval,
        PRUnichar * displayInfo,
        IProgress * * progess
    );

    nsresult (*Cleanup)(IExtPackManager *pThis );

    nsresult (*QueryAllPlugInsForFrontend)(
        IExtPackManager *pThis,
        PRUnichar * frontendName,
        PRUint32 *plugInModulesSize,
        PRUnichar *** plugInModules
    );

    nsresult (*IsExtPackUsable)(
        IExtPackManager *pThis,
        PRUnichar * name,
        PRBool * usable
    );

};

struct IExtPackManager
{
    struct IExtPackManager_vtbl *vtbl;
};
/* End of struct IExtPackManager Declaration */


/* Start of struct IBandwidthGroup Declaration */
#  define IBANDWIDTHGROUP_IID_STR "badea2d7-0261-4146-89f0-6a57cc34833d"
#  define IBANDWIDTHGROUP_IID { \
    0xbadea2d7, 0x0261, 0x4146, \
    { 0x89, 0xf0, 0x6a, 0x57, 0xcc, 0x34, 0x83, 0x3d } \
}
struct IBandwidthGroup_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IBandwidthGroup *pThis, PRUnichar * *name);

    nsresult (*GetType)(IBandwidthGroup *pThis, PRUint32 *type);

    nsresult (*GetReference)(IBandwidthGroup *pThis, PRUint32 *reference);

    nsresult (*GetMaxBytesPerSec)(IBandwidthGroup *pThis, PRInt64 *maxBytesPerSec);
    nsresult (*SetMaxBytesPerSec)(IBandwidthGroup *pThis, PRInt64 maxBytesPerSec);

};

struct IBandwidthGroup
{
    struct IBandwidthGroup_vtbl *vtbl;
};
/* End of struct IBandwidthGroup Declaration */


/* Start of struct IBandwidthControl Declaration */
#  define IBANDWIDTHCONTROL_IID_STR "e2eb3930-d2f4-4f87-be17-0707e30f019f"
#  define IBANDWIDTHCONTROL_IID { \
    0xe2eb3930, 0xd2f4, 0x4f87, \
    { 0xbe, 0x17, 0x07, 0x07, 0xe3, 0x0f, 0x01, 0x9f } \
}
struct IBandwidthControl_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetNumGroups)(IBandwidthControl *pThis, PRUint32 *numGroups);

    nsresult (*CreateBandwidthGroup)(
        IBandwidthControl *pThis,
        PRUnichar * name,
        PRUint32 type,
        PRInt64 maxBytesPerSec
    );

    nsresult (*DeleteBandwidthGroup)(
        IBandwidthControl *pThis,
        PRUnichar * name
    );

    nsresult (*GetBandwidthGroup)(
        IBandwidthControl *pThis,
        PRUnichar * name,
        IBandwidthGroup * * bandwidthGroup
    );

    nsresult (*GetAllBandwidthGroups)(
        IBandwidthControl *pThis,
        PRUint32 *bandwidthGroupsSize,
        IBandwidthGroup *** bandwidthGroups
    );

};

struct IBandwidthControl
{
    struct IBandwidthControl_vtbl *vtbl;
};
/* End of struct IBandwidthControl Declaration */


/* Start of struct IVirtualBoxClient Declaration */
#  define IVIRTUALBOXCLIENT_IID_STR "d191281f-b0cb-4d83-a8fa-0d9fd6ba234c"
#  define IVIRTUALBOXCLIENT_IID { \
    0xd191281f, 0xb0cb, 0x4d83, \
    { 0xa8, 0xfa, 0x0d, 0x9f, 0xd6, 0xba, 0x23, 0x4c } \
}
struct IVirtualBoxClient_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetVirtualBox)(IVirtualBoxClient *pThis, IVirtualBox * *virtualBox);

    nsresult (*GetSession)(IVirtualBoxClient *pThis, ISession * *session);

    nsresult (*GetEventSource)(IVirtualBoxClient *pThis, IEventSource * *eventSource);

    nsresult (*CheckMachineError)(
        IVirtualBoxClient *pThis,
        IMachine * machine
    );

};

struct IVirtualBoxClient
{
    struct IVirtualBoxClient_vtbl *vtbl;
};
/* End of struct IVirtualBoxClient Declaration */


/* Start of struct IEventSource Declaration */
#  define IEVENTSOURCE_IID_STR "9b6e1aee-35f3-4f4d-b5bb-ed0ecefd8538"
#  define IEVENTSOURCE_IID { \
    0x9b6e1aee, 0x35f3, 0x4f4d, \
    { 0xb5, 0xbb, 0xed, 0x0e, 0xce, 0xfd, 0x85, 0x38 } \
}
struct IEventSource_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*CreateListener)(
        IEventSource *pThis,
        IEventListener * * listener
    );

    nsresult (*CreateAggregator)(
        IEventSource *pThis,
        PRUint32 subordinatesSize,
        IEventSource ** subordinates,
        IEventSource * * result
    );

    nsresult (*RegisterListener)(
        IEventSource *pThis,
        IEventListener * listener,
        PRUint32 interestingSize,
        PRUint32* interesting,
        PRBool active
    );

    nsresult (*UnregisterListener)(
        IEventSource *pThis,
        IEventListener * listener
    );

    nsresult (*FireEvent)(
        IEventSource *pThis,
        IEvent * event,
        PRInt32 timeout,
        PRBool * result
    );

    nsresult (*GetEvent)(
        IEventSource *pThis,
        IEventListener * listener,
        PRInt32 timeout,
        IEvent * * event
    );

    nsresult (*EventProcessed)(
        IEventSource *pThis,
        IEventListener * listener,
        IEvent * event
    );

};

struct IEventSource
{
    struct IEventSource_vtbl *vtbl;
};
/* End of struct IEventSource Declaration */


/* Start of struct IEventListener Declaration */
#  define IEVENTLISTENER_IID_STR "67099191-32e7-4f6c-85ee-422304c71b90"
#  define IEVENTLISTENER_IID { \
    0x67099191, 0x32e7, 0x4f6c, \
    { 0x85, 0xee, 0x42, 0x23, 0x04, 0xc7, 0x1b, 0x90 } \
}
struct IEventListener_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*HandleEvent)(
        IEventListener *pThis,
        IEvent * event
    );

};

struct IEventListener
{
    struct IEventListener_vtbl *vtbl;
};
/* End of struct IEventListener Declaration */


/* Start of struct IEvent Declaration */
#  define IEVENT_IID_STR "0ca2adba-8f30-401b-a8cd-fe31dbe839c0"
#  define IEVENT_IID { \
    0x0ca2adba, 0x8f30, 0x401b, \
    { 0xa8, 0xcd, 0xfe, 0x31, 0xdb, 0xe8, 0x39, 0xc0 } \
}
struct IEvent_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetType)(IEvent *pThis, PRUint32 *type);

    nsresult (*GetSource)(IEvent *pThis, IEventSource * *source);

    nsresult (*GetWaitable)(IEvent *pThis, PRBool *waitable);

    nsresult (*SetProcessed)(IEvent *pThis );

    nsresult (*WaitProcessed)(
        IEvent *pThis,
        PRInt32 timeout,
        PRBool * result
    );

};

struct IEvent
{
    struct IEvent_vtbl *vtbl;
};
/* End of struct IEvent Declaration */


/* Start of struct IReusableEvent Declaration */
#  define IREUSABLEEVENT_IID_STR "69bfb134-80f6-4266-8e20-16371f68fa25"
#  define IREUSABLEEVENT_IID { \
    0x69bfb134, 0x80f6, 0x4266, \
    { 0x8e, 0x20, 0x16, 0x37, 0x1f, 0x68, 0xfa, 0x25 } \
}
struct IReusableEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetGeneration)(IReusableEvent *pThis, PRUint32 *generation);

    nsresult (*Reuse)(IReusableEvent *pThis );

};

struct IReusableEvent
{
    struct IReusableEvent_vtbl *vtbl;
};
/* End of struct IReusableEvent Declaration */


/* Start of struct IMachineEvent Declaration */
#  define IMACHINEEVENT_IID_STR "92ed7b1a-0d96-40ed-ae46-a564d484325e"
#  define IMACHINEEVENT_IID { \
    0x92ed7b1a, 0x0d96, 0x40ed, \
    { 0xae, 0x46, 0xa5, 0x64, 0xd4, 0x84, 0x32, 0x5e } \
}
struct IMachineEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetMachineId)(IMachineEvent *pThis, PRUnichar * *machineId);

};

struct IMachineEvent
{
    struct IMachineEvent_vtbl *vtbl;
};
/* End of struct IMachineEvent Declaration */


/* Start of struct IMachineStateChangedEvent Declaration */
#  define IMACHINESTATECHANGEDEVENT_IID_STR "5748F794-48DF-438D-85EB-98FFD70D18C9"
#  define IMACHINESTATECHANGEDEVENT_IID { \
    0x5748F794, 0x48DF, 0x438D, \
    { 0x85, 0xEB, 0x98, 0xFF, 0xD7, 0x0D, 0x18, 0xC9 } \
}
struct IMachineStateChangedEvent_vtbl
{
    struct IMachineEvent_vtbl imachineevent;

    nsresult (*GetState)(IMachineStateChangedEvent *pThis, PRUint32 *state);

};

struct IMachineStateChangedEvent
{
    struct IMachineStateChangedEvent_vtbl *vtbl;
};
/* End of struct IMachineStateChangedEvent Declaration */


/* Start of struct IMachineDataChangedEvent Declaration */
#  define IMACHINEDATACHANGEDEVENT_IID_STR "abe94809-2e88-4436-83d7-50f3e64d0503"
#  define IMACHINEDATACHANGEDEVENT_IID { \
    0xabe94809, 0x2e88, 0x4436, \
    { 0x83, 0xd7, 0x50, 0xf3, 0xe6, 0x4d, 0x05, 0x03 } \
}
struct IMachineDataChangedEvent_vtbl
{
    struct IMachineEvent_vtbl imachineevent;

    nsresult (*GetTemporary)(IMachineDataChangedEvent *pThis, PRBool *temporary);

};

struct IMachineDataChangedEvent
{
    struct IMachineDataChangedEvent_vtbl *vtbl;
};
/* End of struct IMachineDataChangedEvent Declaration */


/* Start of struct IMediumRegisteredEvent Declaration */
#  define IMEDIUMREGISTEREDEVENT_IID_STR "53fac49a-b7f1-4a5a-a4ef-a11dd9c2a458"
#  define IMEDIUMREGISTEREDEVENT_IID { \
    0x53fac49a, 0xb7f1, 0x4a5a, \
    { 0xa4, 0xef, 0xa1, 0x1d, 0xd9, 0xc2, 0xa4, 0x58 } \
}
struct IMediumRegisteredEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetMediumId)(IMediumRegisteredEvent *pThis, PRUnichar * *mediumId);

    nsresult (*GetMediumType)(IMediumRegisteredEvent *pThis, PRUint32 *mediumType);

    nsresult (*GetRegistered)(IMediumRegisteredEvent *pThis, PRBool *registered);

};

struct IMediumRegisteredEvent
{
    struct IMediumRegisteredEvent_vtbl *vtbl;
};
/* End of struct IMediumRegisteredEvent Declaration */


/* Start of struct IMachineRegisteredEvent Declaration */
#  define IMACHINEREGISTEREDEVENT_IID_STR "c354a762-3ff2-4f2e-8f09-07382ee25088"
#  define IMACHINEREGISTEREDEVENT_IID { \
    0xc354a762, 0x3ff2, 0x4f2e, \
    { 0x8f, 0x09, 0x07, 0x38, 0x2e, 0xe2, 0x50, 0x88 } \
}
struct IMachineRegisteredEvent_vtbl
{
    struct IMachineEvent_vtbl imachineevent;

    nsresult (*GetRegistered)(IMachineRegisteredEvent *pThis, PRBool *registered);

};

struct IMachineRegisteredEvent
{
    struct IMachineRegisteredEvent_vtbl *vtbl;
};
/* End of struct IMachineRegisteredEvent Declaration */


/* Start of struct ISessionStateChangedEvent Declaration */
#  define ISESSIONSTATECHANGEDEVENT_IID_STR "714a3eef-799a-4489-86cd-fe8e45b2ff8e"
#  define ISESSIONSTATECHANGEDEVENT_IID { \
    0x714a3eef, 0x799a, 0x4489, \
    { 0x86, 0xcd, 0xfe, 0x8e, 0x45, 0xb2, 0xff, 0x8e } \
}
struct ISessionStateChangedEvent_vtbl
{
    struct IMachineEvent_vtbl imachineevent;

    nsresult (*GetState)(ISessionStateChangedEvent *pThis, PRUint32 *state);

};

struct ISessionStateChangedEvent
{
    struct ISessionStateChangedEvent_vtbl *vtbl;
};
/* End of struct ISessionStateChangedEvent Declaration */


/* Start of struct IGuestPropertyChangedEvent Declaration */
#  define IGUESTPROPERTYCHANGEDEVENT_IID_STR "3f63597a-26f1-4edb-8dd2-6bddd0912368"
#  define IGUESTPROPERTYCHANGEDEVENT_IID { \
    0x3f63597a, 0x26f1, 0x4edb, \
    { 0x8d, 0xd2, 0x6b, 0xdd, 0xd0, 0x91, 0x23, 0x68 } \
}
struct IGuestPropertyChangedEvent_vtbl
{
    struct IMachineEvent_vtbl imachineevent;

    nsresult (*GetName)(IGuestPropertyChangedEvent *pThis, PRUnichar * *name);

    nsresult (*GetValue)(IGuestPropertyChangedEvent *pThis, PRUnichar * *value);

    nsresult (*GetFlags)(IGuestPropertyChangedEvent *pThis, PRUnichar * *flags);

};

struct IGuestPropertyChangedEvent
{
    struct IGuestPropertyChangedEvent_vtbl *vtbl;
};
/* End of struct IGuestPropertyChangedEvent Declaration */


/* Start of struct ISnapshotEvent Declaration */
#  define ISNAPSHOTEVENT_IID_STR "21637b0e-34b8-42d3-acfb-7e96daf77c22"
#  define ISNAPSHOTEVENT_IID { \
    0x21637b0e, 0x34b8, 0x42d3, \
    { 0xac, 0xfb, 0x7e, 0x96, 0xda, 0xf7, 0x7c, 0x22 } \
}
struct ISnapshotEvent_vtbl
{
    struct IMachineEvent_vtbl imachineevent;

    nsresult (*GetSnapshotId)(ISnapshotEvent *pThis, PRUnichar * *snapshotId);

};

struct ISnapshotEvent
{
    struct ISnapshotEvent_vtbl *vtbl;
};
/* End of struct ISnapshotEvent Declaration */


/* Start of struct ISnapshotTakenEvent Declaration */
#  define ISNAPSHOTTAKENEVENT_IID_STR "d27c0b3d-6038-422c-b45e-6d4a0503d9f1"
#  define ISNAPSHOTTAKENEVENT_IID { \
    0xd27c0b3d, 0x6038, 0x422c, \
    { 0xb4, 0x5e, 0x6d, 0x4a, 0x05, 0x03, 0xd9, 0xf1 } \
}
struct ISnapshotTakenEvent_vtbl
{
    struct ISnapshotEvent_vtbl isnapshotevent;

};

struct ISnapshotTakenEvent
{
    struct ISnapshotTakenEvent_vtbl *vtbl;
};
/* End of struct ISnapshotTakenEvent Declaration */


/* Start of struct ISnapshotDeletedEvent Declaration */
#  define ISNAPSHOTDELETEDEVENT_IID_STR "c48f3401-4a9e-43f4-b7a7-54bd285e22f4"
#  define ISNAPSHOTDELETEDEVENT_IID { \
    0xc48f3401, 0x4a9e, 0x43f4, \
    { 0xb7, 0xa7, 0x54, 0xbd, 0x28, 0x5e, 0x22, 0xf4 } \
}
struct ISnapshotDeletedEvent_vtbl
{
    struct ISnapshotEvent_vtbl isnapshotevent;

};

struct ISnapshotDeletedEvent
{
    struct ISnapshotDeletedEvent_vtbl *vtbl;
};
/* End of struct ISnapshotDeletedEvent Declaration */


/* Start of struct ISnapshotChangedEvent Declaration */
#  define ISNAPSHOTCHANGEDEVENT_IID_STR "07541941-8079-447a-a33e-47a69c7980db"
#  define ISNAPSHOTCHANGEDEVENT_IID { \
    0x07541941, 0x8079, 0x447a, \
    { 0xa3, 0x3e, 0x47, 0xa6, 0x9c, 0x79, 0x80, 0xdb } \
}
struct ISnapshotChangedEvent_vtbl
{
    struct ISnapshotEvent_vtbl isnapshotevent;

};

struct ISnapshotChangedEvent
{
    struct ISnapshotChangedEvent_vtbl *vtbl;
};
/* End of struct ISnapshotChangedEvent Declaration */


/* Start of struct IMousePointerShapeChangedEvent Declaration */
#  define IMOUSEPOINTERSHAPECHANGEDEVENT_IID_STR "a6dcf6e8-416b-4181-8c4a-45ec95177aef"
#  define IMOUSEPOINTERSHAPECHANGEDEVENT_IID { \
    0xa6dcf6e8, 0x416b, 0x4181, \
    { 0x8c, 0x4a, 0x45, 0xec, 0x95, 0x17, 0x7a, 0xef } \
}
struct IMousePointerShapeChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetVisible)(IMousePointerShapeChangedEvent *pThis, PRBool *visible);

    nsresult (*GetAlpha)(IMousePointerShapeChangedEvent *pThis, PRBool *alpha);

    nsresult (*GetXhot)(IMousePointerShapeChangedEvent *pThis, PRUint32 *xhot);

    nsresult (*GetYhot)(IMousePointerShapeChangedEvent *pThis, PRUint32 *yhot);

    nsresult (*GetWidth)(IMousePointerShapeChangedEvent *pThis, PRUint32 *width);

    nsresult (*GetHeight)(IMousePointerShapeChangedEvent *pThis, PRUint32 *height);

    nsresult (*GetShape)(IMousePointerShapeChangedEvent *pThis, PRUint32 *shapeSize, PRUint8 **shape);

};

struct IMousePointerShapeChangedEvent
{
    struct IMousePointerShapeChangedEvent_vtbl *vtbl;
};
/* End of struct IMousePointerShapeChangedEvent Declaration */


/* Start of struct IMouseCapabilityChangedEvent Declaration */
#  define IMOUSECAPABILITYCHANGEDEVENT_IID_STR "70e7779a-e64a-4908-804e-371cad23a756"
#  define IMOUSECAPABILITYCHANGEDEVENT_IID { \
    0x70e7779a, 0xe64a, 0x4908, \
    { 0x80, 0x4e, 0x37, 0x1c, 0xad, 0x23, 0xa7, 0x56 } \
}
struct IMouseCapabilityChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetSupportsAbsolute)(IMouseCapabilityChangedEvent *pThis, PRBool *supportsAbsolute);

    nsresult (*GetSupportsRelative)(IMouseCapabilityChangedEvent *pThis, PRBool *supportsRelative);

    nsresult (*GetSupportsMultiTouch)(IMouseCapabilityChangedEvent *pThis, PRBool *supportsMultiTouch);

    nsresult (*GetNeedsHostCursor)(IMouseCapabilityChangedEvent *pThis, PRBool *needsHostCursor);

};

struct IMouseCapabilityChangedEvent
{
    struct IMouseCapabilityChangedEvent_vtbl *vtbl;
};
/* End of struct IMouseCapabilityChangedEvent Declaration */


/* Start of struct IKeyboardLedsChangedEvent Declaration */
#  define IKEYBOARDLEDSCHANGEDEVENT_IID_STR "6DDEF35E-4737-457B-99FC-BC52C851A44F"
#  define IKEYBOARDLEDSCHANGEDEVENT_IID { \
    0x6DDEF35E, 0x4737, 0x457B, \
    { 0x99, 0xFC, 0xBC, 0x52, 0xC8, 0x51, 0xA4, 0x4F } \
}
struct IKeyboardLedsChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetNumLock)(IKeyboardLedsChangedEvent *pThis, PRBool *numLock);

    nsresult (*GetCapsLock)(IKeyboardLedsChangedEvent *pThis, PRBool *capsLock);

    nsresult (*GetScrollLock)(IKeyboardLedsChangedEvent *pThis, PRBool *scrollLock);

};

struct IKeyboardLedsChangedEvent
{
    struct IKeyboardLedsChangedEvent_vtbl *vtbl;
};
/* End of struct IKeyboardLedsChangedEvent Declaration */


/* Start of struct IStateChangedEvent Declaration */
#  define ISTATECHANGEDEVENT_IID_STR "4376693C-CF37-453B-9289-3B0F521CAF27"
#  define ISTATECHANGEDEVENT_IID { \
    0x4376693C, 0xCF37, 0x453B, \
    { 0x92, 0x89, 0x3B, 0x0F, 0x52, 0x1C, 0xAF, 0x27 } \
}
struct IStateChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetState)(IStateChangedEvent *pThis, PRUint32 *state);

};

struct IStateChangedEvent
{
    struct IStateChangedEvent_vtbl *vtbl;
};
/* End of struct IStateChangedEvent Declaration */


/* Start of struct IAdditionsStateChangedEvent Declaration */
#  define IADDITIONSSTATECHANGEDEVENT_IID_STR "D70F7915-DA7C-44C8-A7AC-9F173490446A"
#  define IADDITIONSSTATECHANGEDEVENT_IID { \
    0xD70F7915, 0xDA7C, 0x44C8, \
    { 0xA7, 0xAC, 0x9F, 0x17, 0x34, 0x90, 0x44, 0x6A } \
}
struct IAdditionsStateChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

};

struct IAdditionsStateChangedEvent
{
    struct IAdditionsStateChangedEvent_vtbl *vtbl;
};
/* End of struct IAdditionsStateChangedEvent Declaration */


/* Start of struct INetworkAdapterChangedEvent Declaration */
#  define INETWORKADAPTERCHANGEDEVENT_IID_STR "08889892-1EC6-4883-801D-77F56CFD0103"
#  define INETWORKADAPTERCHANGEDEVENT_IID { \
    0x08889892, 0x1EC6, 0x4883, \
    { 0x80, 0x1D, 0x77, 0xF5, 0x6C, 0xFD, 0x01, 0x03 } \
}
struct INetworkAdapterChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetNetworkAdapter)(INetworkAdapterChangedEvent *pThis, INetworkAdapter * *networkAdapter);

};

struct INetworkAdapterChangedEvent
{
    struct INetworkAdapterChangedEvent_vtbl *vtbl;
};
/* End of struct INetworkAdapterChangedEvent Declaration */


/* Start of struct ISerialPortChangedEvent Declaration */
#  define ISERIALPORTCHANGEDEVENT_IID_STR "3BA329DC-659C-488B-835C-4ECA7AE71C6C"
#  define ISERIALPORTCHANGEDEVENT_IID { \
    0x3BA329DC, 0x659C, 0x488B, \
    { 0x83, 0x5C, 0x4E, 0xCA, 0x7A, 0xE7, 0x1C, 0x6C } \
}
struct ISerialPortChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetSerialPort)(ISerialPortChangedEvent *pThis, ISerialPort * *serialPort);

};

struct ISerialPortChangedEvent
{
    struct ISerialPortChangedEvent_vtbl *vtbl;
};
/* End of struct ISerialPortChangedEvent Declaration */


/* Start of struct IParallelPortChangedEvent Declaration */
#  define IPARALLELPORTCHANGEDEVENT_IID_STR "813C99FC-9849-4F47-813E-24A75DC85615"
#  define IPARALLELPORTCHANGEDEVENT_IID { \
    0x813C99FC, 0x9849, 0x4F47, \
    { 0x81, 0x3E, 0x24, 0xA7, 0x5D, 0xC8, 0x56, 0x15 } \
}
struct IParallelPortChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetParallelPort)(IParallelPortChangedEvent *pThis, IParallelPort * *parallelPort);

};

struct IParallelPortChangedEvent
{
    struct IParallelPortChangedEvent_vtbl *vtbl;
};
/* End of struct IParallelPortChangedEvent Declaration */


/* Start of struct IStorageControllerChangedEvent Declaration */
#  define ISTORAGECONTROLLERCHANGEDEVENT_IID_STR "715212BF-DA59-426E-8230-3831FAA52C56"
#  define ISTORAGECONTROLLERCHANGEDEVENT_IID { \
    0x715212BF, 0xDA59, 0x426E, \
    { 0x82, 0x30, 0x38, 0x31, 0xFA, 0xA5, 0x2C, 0x56 } \
}
struct IStorageControllerChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

};

struct IStorageControllerChangedEvent
{
    struct IStorageControllerChangedEvent_vtbl *vtbl;
};
/* End of struct IStorageControllerChangedEvent Declaration */


/* Start of struct IMediumChangedEvent Declaration */
#  define IMEDIUMCHANGEDEVENT_IID_STR "0FE2DA40-5637-472A-9736-72019EABD7DE"
#  define IMEDIUMCHANGEDEVENT_IID { \
    0x0FE2DA40, 0x5637, 0x472A, \
    { 0x97, 0x36, 0x72, 0x01, 0x9E, 0xAB, 0xD7, 0xDE } \
}
struct IMediumChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetMediumAttachment)(IMediumChangedEvent *pThis, IMediumAttachment * *mediumAttachment);

};

struct IMediumChangedEvent
{
    struct IMediumChangedEvent_vtbl *vtbl;
};
/* End of struct IMediumChangedEvent Declaration */


/* Start of struct IClipboardModeChangedEvent Declaration */
#  define ICLIPBOARDMODECHANGEDEVENT_IID_STR "cac21692-7997-4595-a731-3a509db604e5"
#  define ICLIPBOARDMODECHANGEDEVENT_IID { \
    0xcac21692, 0x7997, 0x4595, \
    { 0xa7, 0x31, 0x3a, 0x50, 0x9d, 0xb6, 0x04, 0xe5 } \
}
struct IClipboardModeChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetClipboardMode)(IClipboardModeChangedEvent *pThis, PRUint32 *clipboardMode);

};

struct IClipboardModeChangedEvent
{
    struct IClipboardModeChangedEvent_vtbl *vtbl;
};
/* End of struct IClipboardModeChangedEvent Declaration */


/* Start of struct IDragAndDropModeChangedEvent Declaration */
#  define IDRAGANDDROPMODECHANGEDEVENT_IID_STR "e90b8850-ac8e-4dff-8059-4100ae2c3c3d"
#  define IDRAGANDDROPMODECHANGEDEVENT_IID { \
    0xe90b8850, 0xac8e, 0x4dff, \
    { 0x80, 0x59, 0x41, 0x00, 0xae, 0x2c, 0x3c, 0x3d } \
}
struct IDragAndDropModeChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetDragAndDropMode)(IDragAndDropModeChangedEvent *pThis, PRUint32 *dragAndDropMode);

};

struct IDragAndDropModeChangedEvent
{
    struct IDragAndDropModeChangedEvent_vtbl *vtbl;
};
/* End of struct IDragAndDropModeChangedEvent Declaration */


/* Start of struct ICPUChangedEvent Declaration */
#  define ICPUCHANGEDEVENT_IID_STR "4da2dec7-71b2-4817-9a64-4ed12c17388e"
#  define ICPUCHANGEDEVENT_IID { \
    0x4da2dec7, 0x71b2, 0x4817, \
    { 0x9a, 0x64, 0x4e, 0xd1, 0x2c, 0x17, 0x38, 0x8e } \
}
struct ICPUChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetCPU)(ICPUChangedEvent *pThis, PRUint32 *CPU);

    nsresult (*GetAdd)(ICPUChangedEvent *pThis, PRBool *add);

};

struct ICPUChangedEvent
{
    struct ICPUChangedEvent_vtbl *vtbl;
};
/* End of struct ICPUChangedEvent Declaration */


/* Start of struct ICPUExecutionCapChangedEvent Declaration */
#  define ICPUEXECUTIONCAPCHANGEDEVENT_IID_STR "dfa7e4f5-b4a4-44ce-85a8-127ac5eb59dc"
#  define ICPUEXECUTIONCAPCHANGEDEVENT_IID { \
    0xdfa7e4f5, 0xb4a4, 0x44ce, \
    { 0x85, 0xa8, 0x12, 0x7a, 0xc5, 0xeb, 0x59, 0xdc } \
}
struct ICPUExecutionCapChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetExecutionCap)(ICPUExecutionCapChangedEvent *pThis, PRUint32 *executionCap);

};

struct ICPUExecutionCapChangedEvent
{
    struct ICPUExecutionCapChangedEvent_vtbl *vtbl;
};
/* End of struct ICPUExecutionCapChangedEvent Declaration */


/* Start of struct IGuestKeyboardEvent Declaration */
#  define IGUESTKEYBOARDEVENT_IID_STR "88394258-7006-40d4-b339-472ee3801844"
#  define IGUESTKEYBOARDEVENT_IID { \
    0x88394258, 0x7006, 0x40d4, \
    { 0xb3, 0x39, 0x47, 0x2e, 0xe3, 0x80, 0x18, 0x44 } \
}
struct IGuestKeyboardEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetScancodes)(IGuestKeyboardEvent *pThis, PRUint32 *scancodesSize, PRInt32 **scancodes);

};

struct IGuestKeyboardEvent
{
    struct IGuestKeyboardEvent_vtbl *vtbl;
};
/* End of struct IGuestKeyboardEvent Declaration */


/* Start of struct IGuestMouseEvent Declaration */
#  define IGUESTMOUSEEVENT_IID_STR "179f8647-319c-4e7e-8150-c5837bd265f6"
#  define IGUESTMOUSEEVENT_IID { \
    0x179f8647, 0x319c, 0x4e7e, \
    { 0x81, 0x50, 0xc5, 0x83, 0x7b, 0xd2, 0x65, 0xf6 } \
}
struct IGuestMouseEvent_vtbl
{
    struct IReusableEvent_vtbl ireusableevent;

    nsresult (*GetMode)(IGuestMouseEvent *pThis, PRUint32 *mode);

    nsresult (*GetX)(IGuestMouseEvent *pThis, PRInt32 *x);

    nsresult (*GetY)(IGuestMouseEvent *pThis, PRInt32 *y);

    nsresult (*GetZ)(IGuestMouseEvent *pThis, PRInt32 *z);

    nsresult (*GetW)(IGuestMouseEvent *pThis, PRInt32 *w);

    nsresult (*GetButtons)(IGuestMouseEvent *pThis, PRInt32 *buttons);

};

struct IGuestMouseEvent
{
    struct IGuestMouseEvent_vtbl *vtbl;
};
/* End of struct IGuestMouseEvent Declaration */


/* Start of struct IGuestMultiTouchEvent Declaration */
#  define IGUESTMULTITOUCHEVENT_IID_STR "be8a0eb5-f4f4-4dd0-9d30-c89b873247ec"
#  define IGUESTMULTITOUCHEVENT_IID { \
    0xbe8a0eb5, 0xf4f4, 0x4dd0, \
    { 0x9d, 0x30, 0xc8, 0x9b, 0x87, 0x32, 0x47, 0xec } \
}
struct IGuestMultiTouchEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetContactCount)(IGuestMultiTouchEvent *pThis, PRInt32 *contactCount);

    nsresult (*GetXPositions)(IGuestMultiTouchEvent *pThis, PRUint32 *xPositionsSize, PRInt16 **xPositions);

    nsresult (*GetYPositions)(IGuestMultiTouchEvent *pThis, PRUint32 *yPositionsSize, PRInt16 **yPositions);

    nsresult (*GetContactIds)(IGuestMultiTouchEvent *pThis, PRUint32 *contactIdsSize, PRUint16 **contactIds);

    nsresult (*GetContactFlags)(IGuestMultiTouchEvent *pThis, PRUint32 *contactFlagsSize, PRUint16 **contactFlags);

    nsresult (*GetScanTime)(IGuestMultiTouchEvent *pThis, PRUint32 *scanTime);

};

struct IGuestMultiTouchEvent
{
    struct IGuestMultiTouchEvent_vtbl *vtbl;
};
/* End of struct IGuestMultiTouchEvent Declaration */


/* Start of struct IGuestSessionEvent Declaration */
#  define IGUESTSESSIONEVENT_IID_STR "b9acd33f-647d-45ac-8fe9-f49b3183ba37"
#  define IGUESTSESSIONEVENT_IID { \
    0xb9acd33f, 0x647d, 0x45ac, \
    { 0x8f, 0xe9, 0xf4, 0x9b, 0x31, 0x83, 0xba, 0x37 } \
}
struct IGuestSessionEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetSession)(IGuestSessionEvent *pThis, IGuestSession * *session);

};

struct IGuestSessionEvent
{
    struct IGuestSessionEvent_vtbl *vtbl;
};
/* End of struct IGuestSessionEvent Declaration */


/* Start of struct IGuestSessionStateChangedEvent Declaration */
#  define IGUESTSESSIONSTATECHANGEDEVENT_IID_STR "327e3c00-ee61-462f-aed3-0dff6cbf9904"
#  define IGUESTSESSIONSTATECHANGEDEVENT_IID { \
    0x327e3c00, 0xee61, 0x462f, \
    { 0xae, 0xd3, 0x0d, 0xff, 0x6c, 0xbf, 0x99, 0x04 } \
}
struct IGuestSessionStateChangedEvent_vtbl
{
    struct IGuestSessionEvent_vtbl iguestsessionevent;

    nsresult (*GetId)(IGuestSessionStateChangedEvent *pThis, PRUint32 *id);

    nsresult (*GetStatus)(IGuestSessionStateChangedEvent *pThis, PRUint32 *status);

    nsresult (*GetError)(IGuestSessionStateChangedEvent *pThis, IVirtualBoxErrorInfo * *error);

};

struct IGuestSessionStateChangedEvent
{
    struct IGuestSessionStateChangedEvent_vtbl *vtbl;
};
/* End of struct IGuestSessionStateChangedEvent Declaration */


/* Start of struct IGuestSessionRegisteredEvent Declaration */
#  define IGUESTSESSIONREGISTEREDEVENT_IID_STR "b79de686-eabd-4fa6-960a-f1756c99ea1c"
#  define IGUESTSESSIONREGISTEREDEVENT_IID { \
    0xb79de686, 0xeabd, 0x4fa6, \
    { 0x96, 0x0a, 0xf1, 0x75, 0x6c, 0x99, 0xea, 0x1c } \
}
struct IGuestSessionRegisteredEvent_vtbl
{
    struct IGuestSessionEvent_vtbl iguestsessionevent;

    nsresult (*GetRegistered)(IGuestSessionRegisteredEvent *pThis, PRBool *registered);

};

struct IGuestSessionRegisteredEvent
{
    struct IGuestSessionRegisteredEvent_vtbl *vtbl;
};
/* End of struct IGuestSessionRegisteredEvent Declaration */


/* Start of struct IGuestProcessEvent Declaration */
#  define IGUESTPROCESSEVENT_IID_STR "2405f0e5-6588-40a3-9b0a-68c05ba52c4b"
#  define IGUESTPROCESSEVENT_IID { \
    0x2405f0e5, 0x6588, 0x40a3, \
    { 0x9b, 0x0a, 0x68, 0xc0, 0x5b, 0xa5, 0x2c, 0x4b } \
}
struct IGuestProcessEvent_vtbl
{
    struct IGuestSessionEvent_vtbl iguestsessionevent;

    nsresult (*GetProcess)(IGuestProcessEvent *pThis, IGuestProcess * *process);

    nsresult (*GetPid)(IGuestProcessEvent *pThis, PRUint32 *pid);

};

struct IGuestProcessEvent
{
    struct IGuestProcessEvent_vtbl *vtbl;
};
/* End of struct IGuestProcessEvent Declaration */


/* Start of struct IGuestProcessRegisteredEvent Declaration */
#  define IGUESTPROCESSREGISTEREDEVENT_IID_STR "1d89e2b3-c6ea-45b6-9d43-dc6f70cc9f02"
#  define IGUESTPROCESSREGISTEREDEVENT_IID { \
    0x1d89e2b3, 0xc6ea, 0x45b6, \
    { 0x9d, 0x43, 0xdc, 0x6f, 0x70, 0xcc, 0x9f, 0x02 } \
}
struct IGuestProcessRegisteredEvent_vtbl
{
    struct IGuestProcessEvent_vtbl iguestprocessevent;

    nsresult (*GetRegistered)(IGuestProcessRegisteredEvent *pThis, PRBool *registered);

};

struct IGuestProcessRegisteredEvent
{
    struct IGuestProcessRegisteredEvent_vtbl *vtbl;
};
/* End of struct IGuestProcessRegisteredEvent Declaration */


/* Start of struct IGuestProcessStateChangedEvent Declaration */
#  define IGUESTPROCESSSTATECHANGEDEVENT_IID_STR "c365fb7b-4430-499f-92c8-8bed814a567a"
#  define IGUESTPROCESSSTATECHANGEDEVENT_IID { \
    0xc365fb7b, 0x4430, 0x499f, \
    { 0x92, 0xc8, 0x8b, 0xed, 0x81, 0x4a, 0x56, 0x7a } \
}
struct IGuestProcessStateChangedEvent_vtbl
{
    struct IGuestProcessEvent_vtbl iguestprocessevent;

    nsresult (*GetStatus)(IGuestProcessStateChangedEvent *pThis, PRUint32 *status);

    nsresult (*GetError)(IGuestProcessStateChangedEvent *pThis, IVirtualBoxErrorInfo * *error);

};

struct IGuestProcessStateChangedEvent
{
    struct IGuestProcessStateChangedEvent_vtbl *vtbl;
};
/* End of struct IGuestProcessStateChangedEvent Declaration */


/* Start of struct IGuestProcessIOEvent Declaration */
#  define IGUESTPROCESSIOEVENT_IID_STR "9ea9227c-e9bb-49b3-bfc7-c5171e93ef38"
#  define IGUESTPROCESSIOEVENT_IID { \
    0x9ea9227c, 0xe9bb, 0x49b3, \
    { 0xbf, 0xc7, 0xc5, 0x17, 0x1e, 0x93, 0xef, 0x38 } \
}
struct IGuestProcessIOEvent_vtbl
{
    struct IGuestProcessEvent_vtbl iguestprocessevent;

    nsresult (*GetHandle)(IGuestProcessIOEvent *pThis, PRUint32 *handle);

    nsresult (*GetProcessed)(IGuestProcessIOEvent *pThis, PRUint32 *processed);

};

struct IGuestProcessIOEvent
{
    struct IGuestProcessIOEvent_vtbl *vtbl;
};
/* End of struct IGuestProcessIOEvent Declaration */


/* Start of struct IGuestProcessInputNotifyEvent Declaration */
#  define IGUESTPROCESSINPUTNOTIFYEVENT_IID_STR "0de887f2-b7db-4616-aac6-cfb94d89ba78"
#  define IGUESTPROCESSINPUTNOTIFYEVENT_IID { \
    0x0de887f2, 0xb7db, 0x4616, \
    { 0xaa, 0xc6, 0xcf, 0xb9, 0x4d, 0x89, 0xba, 0x78 } \
}
struct IGuestProcessInputNotifyEvent_vtbl
{
    struct IGuestProcessIOEvent_vtbl iguestprocessioevent;

    nsresult (*GetStatus)(IGuestProcessInputNotifyEvent *pThis, PRUint32 *status);

};

struct IGuestProcessInputNotifyEvent
{
    struct IGuestProcessInputNotifyEvent_vtbl *vtbl;
};
/* End of struct IGuestProcessInputNotifyEvent Declaration */


/* Start of struct IGuestProcessOutputEvent Declaration */
#  define IGUESTPROCESSOUTPUTEVENT_IID_STR "d3d5f1ee-bcb2-4905-a7ab-cc85448a742b"
#  define IGUESTPROCESSOUTPUTEVENT_IID { \
    0xd3d5f1ee, 0xbcb2, 0x4905, \
    { 0xa7, 0xab, 0xcc, 0x85, 0x44, 0x8a, 0x74, 0x2b } \
}
struct IGuestProcessOutputEvent_vtbl
{
    struct IGuestProcessIOEvent_vtbl iguestprocessioevent;

    nsresult (*GetData)(IGuestProcessOutputEvent *pThis, PRUint32 *dataSize, PRUint8 **data);

};

struct IGuestProcessOutputEvent
{
    struct IGuestProcessOutputEvent_vtbl *vtbl;
};
/* End of struct IGuestProcessOutputEvent Declaration */


/* Start of struct IGuestFileEvent Declaration */
#  define IGUESTFILEEVENT_IID_STR "c8adb7b0-057d-4391-b928-f14b06b710c5"
#  define IGUESTFILEEVENT_IID { \
    0xc8adb7b0, 0x057d, 0x4391, \
    { 0xb9, 0x28, 0xf1, 0x4b, 0x06, 0xb7, 0x10, 0xc5 } \
}
struct IGuestFileEvent_vtbl
{
    struct IGuestSessionEvent_vtbl iguestsessionevent;

    nsresult (*GetFile)(IGuestFileEvent *pThis, IGuestFile * *file);

};

struct IGuestFileEvent
{
    struct IGuestFileEvent_vtbl *vtbl;
};
/* End of struct IGuestFileEvent Declaration */


/* Start of struct IGuestFileRegisteredEvent Declaration */
#  define IGUESTFILEREGISTEREDEVENT_IID_STR "d0d93830-70a2-487e-895e-d3fc9679f7b3"
#  define IGUESTFILEREGISTEREDEVENT_IID { \
    0xd0d93830, 0x70a2, 0x487e, \
    { 0x89, 0x5e, 0xd3, 0xfc, 0x96, 0x79, 0xf7, 0xb3 } \
}
struct IGuestFileRegisteredEvent_vtbl
{
    struct IGuestFileEvent_vtbl iguestfileevent;

    nsresult (*GetRegistered)(IGuestFileRegisteredEvent *pThis, PRBool *registered);

};

struct IGuestFileRegisteredEvent
{
    struct IGuestFileRegisteredEvent_vtbl *vtbl;
};
/* End of struct IGuestFileRegisteredEvent Declaration */


/* Start of struct IGuestFileStateChangedEvent Declaration */
#  define IGUESTFILESTATECHANGEDEVENT_IID_STR "d37fe88f-0979-486c-baa1-3abb144dc82d"
#  define IGUESTFILESTATECHANGEDEVENT_IID { \
    0xd37fe88f, 0x0979, 0x486c, \
    { 0xba, 0xa1, 0x3a, 0xbb, 0x14, 0x4d, 0xc8, 0x2d } \
}
struct IGuestFileStateChangedEvent_vtbl
{
    struct IGuestFileEvent_vtbl iguestfileevent;

    nsresult (*GetStatus)(IGuestFileStateChangedEvent *pThis, PRUint32 *status);

    nsresult (*GetError)(IGuestFileStateChangedEvent *pThis, IVirtualBoxErrorInfo * *error);

};

struct IGuestFileStateChangedEvent
{
    struct IGuestFileStateChangedEvent_vtbl *vtbl;
};
/* End of struct IGuestFileStateChangedEvent Declaration */


/* Start of struct IGuestFileIOEvent Declaration */
#  define IGUESTFILEIOEVENT_IID_STR "b5191a7c-9536-4ef8-820e-3b0e17e5bbc8"
#  define IGUESTFILEIOEVENT_IID { \
    0xb5191a7c, 0x9536, 0x4ef8, \
    { 0x82, 0x0e, 0x3b, 0x0e, 0x17, 0xe5, 0xbb, 0xc8 } \
}
struct IGuestFileIOEvent_vtbl
{
    struct IGuestFileEvent_vtbl iguestfileevent;

    nsresult (*GetOffset)(IGuestFileIOEvent *pThis, PRInt64 *offset);

    nsresult (*GetProcessed)(IGuestFileIOEvent *pThis, PRUint32 *processed);

};

struct IGuestFileIOEvent
{
    struct IGuestFileIOEvent_vtbl *vtbl;
};
/* End of struct IGuestFileIOEvent Declaration */


/* Start of struct IGuestFileOffsetChangedEvent Declaration */
#  define IGUESTFILEOFFSETCHANGEDEVENT_IID_STR "e8f79a21-1207-4179-94cf-ca250036308f"
#  define IGUESTFILEOFFSETCHANGEDEVENT_IID { \
    0xe8f79a21, 0x1207, 0x4179, \
    { 0x94, 0xcf, 0xca, 0x25, 0x00, 0x36, 0x30, 0x8f } \
}
struct IGuestFileOffsetChangedEvent_vtbl
{
    struct IGuestFileIOEvent_vtbl iguestfileioevent;

};

struct IGuestFileOffsetChangedEvent
{
    struct IGuestFileOffsetChangedEvent_vtbl *vtbl;
};
/* End of struct IGuestFileOffsetChangedEvent Declaration */


/* Start of struct IGuestFileReadEvent Declaration */
#  define IGUESTFILEREADEVENT_IID_STR "4ee3cbcb-486f-40db-9150-deee3fd24189"
#  define IGUESTFILEREADEVENT_IID { \
    0x4ee3cbcb, 0x486f, 0x40db, \
    { 0x91, 0x50, 0xde, 0xee, 0x3f, 0xd2, 0x41, 0x89 } \
}
struct IGuestFileReadEvent_vtbl
{
    struct IGuestFileIOEvent_vtbl iguestfileioevent;

    nsresult (*GetData)(IGuestFileReadEvent *pThis, PRUint32 *dataSize, PRUint8 **data);

};

struct IGuestFileReadEvent
{
    struct IGuestFileReadEvent_vtbl *vtbl;
};
/* End of struct IGuestFileReadEvent Declaration */


/* Start of struct IGuestFileWriteEvent Declaration */
#  define IGUESTFILEWRITEEVENT_IID_STR "e062a915-3cf5-4c0a-bc90-9b8d4cc94d89"
#  define IGUESTFILEWRITEEVENT_IID { \
    0xe062a915, 0x3cf5, 0x4c0a, \
    { 0xbc, 0x90, 0x9b, 0x8d, 0x4c, 0xc9, 0x4d, 0x89 } \
}
struct IGuestFileWriteEvent_vtbl
{
    struct IGuestFileIOEvent_vtbl iguestfileioevent;

};

struct IGuestFileWriteEvent
{
    struct IGuestFileWriteEvent_vtbl *vtbl;
};
/* End of struct IGuestFileWriteEvent Declaration */


/* Start of struct IVRDEServerChangedEvent Declaration */
#  define IVRDESERVERCHANGEDEVENT_IID_STR "a06fd66a-3188-4c8c-8756-1395e8cb691c"
#  define IVRDESERVERCHANGEDEVENT_IID { \
    0xa06fd66a, 0x3188, 0x4c8c, \
    { 0x87, 0x56, 0x13, 0x95, 0xe8, 0xcb, 0x69, 0x1c } \
}
struct IVRDEServerChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

};

struct IVRDEServerChangedEvent
{
    struct IVRDEServerChangedEvent_vtbl *vtbl;
};
/* End of struct IVRDEServerChangedEvent Declaration */


/* Start of struct IVRDEServerInfoChangedEvent Declaration */
#  define IVRDESERVERINFOCHANGEDEVENT_IID_STR "dd6a1080-e1b7-4339-a549-f0878115596e"
#  define IVRDESERVERINFOCHANGEDEVENT_IID { \
    0xdd6a1080, 0xe1b7, 0x4339, \
    { 0xa5, 0x49, 0xf0, 0x87, 0x81, 0x15, 0x59, 0x6e } \
}
struct IVRDEServerInfoChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

};

struct IVRDEServerInfoChangedEvent
{
    struct IVRDEServerInfoChangedEvent_vtbl *vtbl;
};
/* End of struct IVRDEServerInfoChangedEvent Declaration */


/* Start of struct IVideoCaptureChangedEvent Declaration */
#  define IVIDEOCAPTURECHANGEDEVENT_IID_STR "6215d169-25dd-4719-ab34-c908701efb58"
#  define IVIDEOCAPTURECHANGEDEVENT_IID { \
    0x6215d169, 0x25dd, 0x4719, \
    { 0xab, 0x34, 0xc9, 0x08, 0x70, 0x1e, 0xfb, 0x58 } \
}
struct IVideoCaptureChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

};

struct IVideoCaptureChangedEvent
{
    struct IVideoCaptureChangedEvent_vtbl *vtbl;
};
/* End of struct IVideoCaptureChangedEvent Declaration */


/* Start of struct IUSBControllerChangedEvent Declaration */
#  define IUSBCONTROLLERCHANGEDEVENT_IID_STR "93BADC0C-61D9-4940-A084-E6BB29AF3D83"
#  define IUSBCONTROLLERCHANGEDEVENT_IID { \
    0x93BADC0C, 0x61D9, 0x4940, \
    { 0xA0, 0x84, 0xE6, 0xBB, 0x29, 0xAF, 0x3D, 0x83 } \
}
struct IUSBControllerChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

};

struct IUSBControllerChangedEvent
{
    struct IUSBControllerChangedEvent_vtbl *vtbl;
};
/* End of struct IUSBControllerChangedEvent Declaration */


/* Start of struct IUSBDeviceStateChangedEvent Declaration */
#  define IUSBDEVICESTATECHANGEDEVENT_IID_STR "806da61b-6679-422a-b629-51b06b0c6d93"
#  define IUSBDEVICESTATECHANGEDEVENT_IID { \
    0x806da61b, 0x6679, 0x422a, \
    { 0xb6, 0x29, 0x51, 0xb0, 0x6b, 0x0c, 0x6d, 0x93 } \
}
struct IUSBDeviceStateChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetDevice)(IUSBDeviceStateChangedEvent *pThis, IUSBDevice * *device);

    nsresult (*GetAttached)(IUSBDeviceStateChangedEvent *pThis, PRBool *attached);

    nsresult (*GetError)(IUSBDeviceStateChangedEvent *pThis, IVirtualBoxErrorInfo * *error);

};

struct IUSBDeviceStateChangedEvent
{
    struct IUSBDeviceStateChangedEvent_vtbl *vtbl;
};
/* End of struct IUSBDeviceStateChangedEvent Declaration */


/* Start of struct ISharedFolderChangedEvent Declaration */
#  define ISHAREDFOLDERCHANGEDEVENT_IID_STR "B66349B5-3534-4239-B2DE-8E1535D94C0B"
#  define ISHAREDFOLDERCHANGEDEVENT_IID { \
    0xB66349B5, 0x3534, 0x4239, \
    { 0xB2, 0xDE, 0x8E, 0x15, 0x35, 0xD9, 0x4C, 0x0B } \
}
struct ISharedFolderChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetScope)(ISharedFolderChangedEvent *pThis, PRUint32 *scope);

};

struct ISharedFolderChangedEvent
{
    struct ISharedFolderChangedEvent_vtbl *vtbl;
};
/* End of struct ISharedFolderChangedEvent Declaration */


/* Start of struct IRuntimeErrorEvent Declaration */
#  define IRUNTIMEERROREVENT_IID_STR "883DD18B-0721-4CDE-867C-1A82ABAF914C"
#  define IRUNTIMEERROREVENT_IID { \
    0x883DD18B, 0x0721, 0x4CDE, \
    { 0x86, 0x7C, 0x1A, 0x82, 0xAB, 0xAF, 0x91, 0x4C } \
}
struct IRuntimeErrorEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetFatal)(IRuntimeErrorEvent *pThis, PRBool *fatal);

    nsresult (*GetId)(IRuntimeErrorEvent *pThis, PRUnichar * *id);

    nsresult (*GetMessage)(IRuntimeErrorEvent *pThis, PRUnichar * *message);

};

struct IRuntimeErrorEvent
{
    struct IRuntimeErrorEvent_vtbl *vtbl;
};
/* End of struct IRuntimeErrorEvent Declaration */


/* Start of struct IEventSourceChangedEvent Declaration */
#  define IEVENTSOURCECHANGEDEVENT_IID_STR "e7932cb8-f6d4-4ab6-9cbf-558eb8959a6a"
#  define IEVENTSOURCECHANGEDEVENT_IID { \
    0xe7932cb8, 0xf6d4, 0x4ab6, \
    { 0x9c, 0xbf, 0x55, 0x8e, 0xb8, 0x95, 0x9a, 0x6a } \
}
struct IEventSourceChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetListener)(IEventSourceChangedEvent *pThis, IEventListener * *listener);

    nsresult (*GetAdd)(IEventSourceChangedEvent *pThis, PRBool *add);

};

struct IEventSourceChangedEvent
{
    struct IEventSourceChangedEvent_vtbl *vtbl;
};
/* End of struct IEventSourceChangedEvent Declaration */


/* Start of struct IExtraDataChangedEvent Declaration */
#  define IEXTRADATACHANGEDEVENT_IID_STR "024F00CE-6E0B-492A-A8D0-968472A94DC7"
#  define IEXTRADATACHANGEDEVENT_IID { \
    0x024F00CE, 0x6E0B, 0x492A, \
    { 0xA8, 0xD0, 0x96, 0x84, 0x72, 0xA9, 0x4D, 0xC7 } \
}
struct IExtraDataChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetMachineId)(IExtraDataChangedEvent *pThis, PRUnichar * *machineId);

    nsresult (*GetKey)(IExtraDataChangedEvent *pThis, PRUnichar * *key);

    nsresult (*GetValue)(IExtraDataChangedEvent *pThis, PRUnichar * *value);

};

struct IExtraDataChangedEvent
{
    struct IExtraDataChangedEvent_vtbl *vtbl;
};
/* End of struct IExtraDataChangedEvent Declaration */


/* Start of struct IVetoEvent Declaration */
#  define IVETOEVENT_IID_STR "9a1a4130-69fe-472f-ac10-c6fa25d75007"
#  define IVETOEVENT_IID { \
    0x9a1a4130, 0x69fe, 0x472f, \
    { 0xac, 0x10, 0xc6, 0xfa, 0x25, 0xd7, 0x50, 0x07 } \
}
struct IVetoEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*AddVeto)(
        IVetoEvent *pThis,
        PRUnichar * reason
    );

    nsresult (*IsVetoed)(
        IVetoEvent *pThis,
        PRBool * result
    );

    nsresult (*GetVetos)(
        IVetoEvent *pThis,
        PRUint32 *resultSize,
        PRUnichar *** result
    );

};

struct IVetoEvent
{
    struct IVetoEvent_vtbl *vtbl;
};
/* End of struct IVetoEvent Declaration */


/* Start of struct IExtraDataCanChangeEvent Declaration */
#  define IEXTRADATACANCHANGEEVENT_IID_STR "245d88bd-800a-40f8-87a6-170d02249a55"
#  define IEXTRADATACANCHANGEEVENT_IID { \
    0x245d88bd, 0x800a, 0x40f8, \
    { 0x87, 0xa6, 0x17, 0x0d, 0x02, 0x24, 0x9a, 0x55 } \
}
struct IExtraDataCanChangeEvent_vtbl
{
    struct IVetoEvent_vtbl ivetoevent;

    nsresult (*GetMachineId)(IExtraDataCanChangeEvent *pThis, PRUnichar * *machineId);

    nsresult (*GetKey)(IExtraDataCanChangeEvent *pThis, PRUnichar * *key);

    nsresult (*GetValue)(IExtraDataCanChangeEvent *pThis, PRUnichar * *value);

};

struct IExtraDataCanChangeEvent
{
    struct IExtraDataCanChangeEvent_vtbl *vtbl;
};
/* End of struct IExtraDataCanChangeEvent Declaration */


/* Start of struct ICanShowWindowEvent Declaration */
#  define ICANSHOWWINDOWEVENT_IID_STR "adf292b0-92c9-4a77-9d35-e058b39fe0b9"
#  define ICANSHOWWINDOWEVENT_IID { \
    0xadf292b0, 0x92c9, 0x4a77, \
    { 0x9d, 0x35, 0xe0, 0x58, 0xb3, 0x9f, 0xe0, 0xb9 } \
}
struct ICanShowWindowEvent_vtbl
{
    struct IVetoEvent_vtbl ivetoevent;

};

struct ICanShowWindowEvent
{
    struct ICanShowWindowEvent_vtbl *vtbl;
};
/* End of struct ICanShowWindowEvent Declaration */


/* Start of struct IShowWindowEvent Declaration */
#  define ISHOWWINDOWEVENT_IID_STR "B0A0904D-2F05-4D28-855F-488F96BAD2B2"
#  define ISHOWWINDOWEVENT_IID { \
    0xB0A0904D, 0x2F05, 0x4D28, \
    { 0x85, 0x5F, 0x48, 0x8F, 0x96, 0xBA, 0xD2, 0xB2 } \
}
struct IShowWindowEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetWinId)(IShowWindowEvent *pThis, PRInt64 *winId);
    nsresult (*SetWinId)(IShowWindowEvent *pThis, PRInt64 winId);

};

struct IShowWindowEvent
{
    struct IShowWindowEvent_vtbl *vtbl;
};
/* End of struct IShowWindowEvent Declaration */


/* Start of struct INATRedirectEvent Declaration */
#  define INATREDIRECTEVENT_IID_STR "24eef068-c380-4510-bc7c-19314a7352f1"
#  define INATREDIRECTEVENT_IID { \
    0x24eef068, 0xc380, 0x4510, \
    { 0xbc, 0x7c, 0x19, 0x31, 0x4a, 0x73, 0x52, 0xf1 } \
}
struct INATRedirectEvent_vtbl
{
    struct IMachineEvent_vtbl imachineevent;

    nsresult (*GetSlot)(INATRedirectEvent *pThis, PRUint32 *slot);

    nsresult (*GetRemove)(INATRedirectEvent *pThis, PRBool *remove);

    nsresult (*GetName)(INATRedirectEvent *pThis, PRUnichar * *name);

    nsresult (*GetProto)(INATRedirectEvent *pThis, PRUint32 *proto);

    nsresult (*GetHostIP)(INATRedirectEvent *pThis, PRUnichar * *hostIP);

    nsresult (*GetHostPort)(INATRedirectEvent *pThis, PRInt32 *hostPort);

    nsresult (*GetGuestIP)(INATRedirectEvent *pThis, PRUnichar * *guestIP);

    nsresult (*GetGuestPort)(INATRedirectEvent *pThis, PRInt32 *guestPort);

};

struct INATRedirectEvent
{
    struct INATRedirectEvent_vtbl *vtbl;
};
/* End of struct INATRedirectEvent Declaration */


/* Start of struct IHostPCIDevicePlugEvent Declaration */
#  define IHOSTPCIDEVICEPLUGEVENT_IID_STR "a0bad6df-d612-47d3-89d4-db3992533948"
#  define IHOSTPCIDEVICEPLUGEVENT_IID { \
    0xa0bad6df, 0xd612, 0x47d3, \
    { 0x89, 0xd4, 0xdb, 0x39, 0x92, 0x53, 0x39, 0x48 } \
}
struct IHostPCIDevicePlugEvent_vtbl
{
    struct IMachineEvent_vtbl imachineevent;

    nsresult (*GetPlugged)(IHostPCIDevicePlugEvent *pThis, PRBool *plugged);

    nsresult (*GetSuccess)(IHostPCIDevicePlugEvent *pThis, PRBool *success);

    nsresult (*GetAttachment)(IHostPCIDevicePlugEvent *pThis, IPCIDeviceAttachment * *attachment);

    nsresult (*GetMessage)(IHostPCIDevicePlugEvent *pThis, PRUnichar * *message);

};

struct IHostPCIDevicePlugEvent
{
    struct IHostPCIDevicePlugEvent_vtbl *vtbl;
};
/* End of struct IHostPCIDevicePlugEvent Declaration */


/* Start of struct IVBoxSVCAvailabilityChangedEvent Declaration */
#  define IVBOXSVCAVAILABILITYCHANGEDEVENT_IID_STR "97c78fcd-d4fc-485f-8613-5af88bfcfcdc"
#  define IVBOXSVCAVAILABILITYCHANGEDEVENT_IID { \
    0x97c78fcd, 0xd4fc, 0x485f, \
    { 0x86, 0x13, 0x5a, 0xf8, 0x8b, 0xfc, 0xfc, 0xdc } \
}
struct IVBoxSVCAvailabilityChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetAvailable)(IVBoxSVCAvailabilityChangedEvent *pThis, PRBool *available);

};

struct IVBoxSVCAvailabilityChangedEvent
{
    struct IVBoxSVCAvailabilityChangedEvent_vtbl *vtbl;
};
/* End of struct IVBoxSVCAvailabilityChangedEvent Declaration */


/* Start of struct IBandwidthGroupChangedEvent Declaration */
#  define IBANDWIDTHGROUPCHANGEDEVENT_IID_STR "334df94a-7556-4cbc-8c04-043096b02d82"
#  define IBANDWIDTHGROUPCHANGEDEVENT_IID { \
    0x334df94a, 0x7556, 0x4cbc, \
    { 0x8c, 0x04, 0x04, 0x30, 0x96, 0xb0, 0x2d, 0x82 } \
}
struct IBandwidthGroupChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetBandwidthGroup)(IBandwidthGroupChangedEvent *pThis, IBandwidthGroup * *bandwidthGroup);

};

struct IBandwidthGroupChangedEvent
{
    struct IBandwidthGroupChangedEvent_vtbl *vtbl;
};
/* End of struct IBandwidthGroupChangedEvent Declaration */


/* Start of struct IGuestMonitorChangedEvent Declaration */
#  define IGUESTMONITORCHANGEDEVENT_IID_STR "0f7b8a22-c71f-4a36-8e5f-a77d01d76090"
#  define IGUESTMONITORCHANGEDEVENT_IID { \
    0x0f7b8a22, 0xc71f, 0x4a36, \
    { 0x8e, 0x5f, 0xa7, 0x7d, 0x01, 0xd7, 0x60, 0x90 } \
}
struct IGuestMonitorChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetChangeType)(IGuestMonitorChangedEvent *pThis, PRUint32 *changeType);

    nsresult (*GetScreenId)(IGuestMonitorChangedEvent *pThis, PRUint32 *screenId);

    nsresult (*GetOriginX)(IGuestMonitorChangedEvent *pThis, PRUint32 *originX);

    nsresult (*GetOriginY)(IGuestMonitorChangedEvent *pThis, PRUint32 *originY);

    nsresult (*GetWidth)(IGuestMonitorChangedEvent *pThis, PRUint32 *width);

    nsresult (*GetHeight)(IGuestMonitorChangedEvent *pThis, PRUint32 *height);

};

struct IGuestMonitorChangedEvent
{
    struct IGuestMonitorChangedEvent_vtbl *vtbl;
};
/* End of struct IGuestMonitorChangedEvent Declaration */


/* Start of struct IGuestUserStateChangedEvent Declaration */
#  define IGUESTUSERSTATECHANGEDEVENT_IID_STR "39b4e759-1ec0-4c0f-857f-fbe2a737a256"
#  define IGUESTUSERSTATECHANGEDEVENT_IID { \
    0x39b4e759, 0x1ec0, 0x4c0f, \
    { 0x85, 0x7f, 0xfb, 0xe2, 0xa7, 0x37, 0xa2, 0x56 } \
}
struct IGuestUserStateChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetName)(IGuestUserStateChangedEvent *pThis, PRUnichar * *name);

    nsresult (*GetDomain)(IGuestUserStateChangedEvent *pThis, PRUnichar * *domain);

    nsresult (*GetState)(IGuestUserStateChangedEvent *pThis, PRUint32 *state);

    nsresult (*GetStateDetails)(IGuestUserStateChangedEvent *pThis, PRUnichar * *stateDetails);

};

struct IGuestUserStateChangedEvent
{
    struct IGuestUserStateChangedEvent_vtbl *vtbl;
};
/* End of struct IGuestUserStateChangedEvent Declaration */


/* Start of struct IStorageDeviceChangedEvent Declaration */
#  define ISTORAGEDEVICECHANGEDEVENT_IID_STR "232e9151-ae84-4b8e-b0f3-5c20c35caac9"
#  define ISTORAGEDEVICECHANGEDEVENT_IID { \
    0x232e9151, 0xae84, 0x4b8e, \
    { 0xb0, 0xf3, 0x5c, 0x20, 0xc3, 0x5c, 0xaa, 0xc9 } \
}
struct IStorageDeviceChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetStorageDevice)(IStorageDeviceChangedEvent *pThis, IMediumAttachment * *storageDevice);

    nsresult (*GetRemoved)(IStorageDeviceChangedEvent *pThis, PRBool *removed);

    nsresult (*GetSilent)(IStorageDeviceChangedEvent *pThis, PRBool *silent);

};

struct IStorageDeviceChangedEvent
{
    struct IStorageDeviceChangedEvent_vtbl *vtbl;
};
/* End of struct IStorageDeviceChangedEvent Declaration */


/* Start of struct INATNetworkChangedEvent Declaration */
#  define INATNETWORKCHANGEDEVENT_IID_STR "101ae042-1a29-4a19-92cf-02285773f3b5"
#  define INATNETWORKCHANGEDEVENT_IID { \
    0x101ae042, 0x1a29, 0x4a19, \
    { 0x92, 0xcf, 0x02, 0x28, 0x57, 0x73, 0xf3, 0xb5 } \
}
struct INATNetworkChangedEvent_vtbl
{
    struct IEvent_vtbl ievent;

    nsresult (*GetNetworkName)(INATNetworkChangedEvent *pThis, PRUnichar * *networkName);

};

struct INATNetworkChangedEvent
{
    struct INATNetworkChangedEvent_vtbl *vtbl;
};
/* End of struct INATNetworkChangedEvent Declaration */


/* Start of struct INATNetworkStartStopEvent Declaration */
#  define INATNETWORKSTARTSTOPEVENT_IID_STR "269d8f6b-fa1e-4cee-91c7-6d8496bea3c1"
#  define INATNETWORKSTARTSTOPEVENT_IID { \
    0x269d8f6b, 0xfa1e, 0x4cee, \
    { 0x91, 0xc7, 0x6d, 0x84, 0x96, 0xbe, 0xa3, 0xc1 } \
}
struct INATNetworkStartStopEvent_vtbl
{
    struct INATNetworkChangedEvent_vtbl inatnetworkchangedevent;

    nsresult (*GetStartEvent)(INATNetworkStartStopEvent *pThis, PRBool *startEvent);

};

struct INATNetworkStartStopEvent
{
    struct INATNetworkStartStopEvent_vtbl *vtbl;
};
/* End of struct INATNetworkStartStopEvent Declaration */


/* Start of struct INATNetworkAlterEvent Declaration */
#  define INATNETWORKALTEREVENT_IID_STR "3f5a0822-163a-43b1-ad16-8d58b0ef6e75"
#  define INATNETWORKALTEREVENT_IID { \
    0x3f5a0822, 0x163a, 0x43b1, \
    { 0xad, 0x16, 0x8d, 0x58, 0xb0, 0xef, 0x6e, 0x75 } \
}
struct INATNetworkAlterEvent_vtbl
{
    struct INATNetworkChangedEvent_vtbl inatnetworkchangedevent;

};

struct INATNetworkAlterEvent
{
    struct INATNetworkAlterEvent_vtbl *vtbl;
};
/* End of struct INATNetworkAlterEvent Declaration */


/* Start of struct INATNetworkCreationDeletionEvent Declaration */
#  define INATNETWORKCREATIONDELETIONEVENT_IID_STR "8d984a7e-b855-40b8-ab0c-44d3515b4528"
#  define INATNETWORKCREATIONDELETIONEVENT_IID { \
    0x8d984a7e, 0xb855, 0x40b8, \
    { 0xab, 0x0c, 0x44, 0xd3, 0x51, 0x5b, 0x45, 0x28 } \
}
struct INATNetworkCreationDeletionEvent_vtbl
{
    struct INATNetworkAlterEvent_vtbl inatnetworkalterevent;

    nsresult (*GetCreationEvent)(INATNetworkCreationDeletionEvent *pThis, PRBool *creationEvent);

};

struct INATNetworkCreationDeletionEvent
{
    struct INATNetworkCreationDeletionEvent_vtbl *vtbl;
};
/* End of struct INATNetworkCreationDeletionEvent Declaration */


/* Start of struct INATNetworkSettingEvent Declaration */
#  define INATNETWORKSETTINGEVENT_IID_STR "9db3a9e6-7f29-4aae-a627-5a282c83092c"
#  define INATNETWORKSETTINGEVENT_IID { \
    0x9db3a9e6, 0x7f29, 0x4aae, \
    { 0xa6, 0x27, 0x5a, 0x28, 0x2c, 0x83, 0x09, 0x2c } \
}
struct INATNetworkSettingEvent_vtbl
{
    struct INATNetworkAlterEvent_vtbl inatnetworkalterevent;

    nsresult (*GetEnabled)(INATNetworkSettingEvent *pThis, PRBool *enabled);

    nsresult (*GetNetwork)(INATNetworkSettingEvent *pThis, PRUnichar * *network);

    nsresult (*GetGateway)(INATNetworkSettingEvent *pThis, PRUnichar * *gateway);

    nsresult (*GetAdvertiseDefaultIPv6RouteEnabled)(INATNetworkSettingEvent *pThis, PRBool *advertiseDefaultIPv6RouteEnabled);

    nsresult (*GetNeedDhcpServer)(INATNetworkSettingEvent *pThis, PRBool *needDhcpServer);

};

struct INATNetworkSettingEvent
{
    struct INATNetworkSettingEvent_vtbl *vtbl;
};
/* End of struct INATNetworkSettingEvent Declaration */


/* Start of struct INATNetworkPortForwardEvent Declaration */
#  define INATNETWORKPORTFORWARDEVENT_IID_STR "2514881b-23d0-430a-a7ff-7ed7f05534bc"
#  define INATNETWORKPORTFORWARDEVENT_IID { \
    0x2514881b, 0x23d0, 0x430a, \
    { 0xa7, 0xff, 0x7e, 0xd7, 0xf0, 0x55, 0x34, 0xbc } \
}
struct INATNetworkPortForwardEvent_vtbl
{
    struct INATNetworkAlterEvent_vtbl inatnetworkalterevent;

    nsresult (*GetCreate)(INATNetworkPortForwardEvent *pThis, PRBool *create);

    nsresult (*GetIpv6)(INATNetworkPortForwardEvent *pThis, PRBool *ipv6);

    nsresult (*GetName)(INATNetworkPortForwardEvent *pThis, PRUnichar * *name);

    nsresult (*GetProto)(INATNetworkPortForwardEvent *pThis, PRUint32 *proto);

    nsresult (*GetHostIp)(INATNetworkPortForwardEvent *pThis, PRUnichar * *hostIp);

    nsresult (*GetHostPort)(INATNetworkPortForwardEvent *pThis, PRInt32 *hostPort);

    nsresult (*GetGuestIp)(INATNetworkPortForwardEvent *pThis, PRUnichar * *guestIp);

    nsresult (*GetGuestPort)(INATNetworkPortForwardEvent *pThis, PRInt32 *guestPort);

};

struct INATNetworkPortForwardEvent
{
    struct INATNetworkPortForwardEvent_vtbl *vtbl;
};
/* End of struct INATNetworkPortForwardEvent Declaration */


/* Start of struct IHostNameResolutionConfigurationChangeEvent Declaration */
#  define IHOSTNAMERESOLUTIONCONFIGURATIONCHANGEEVENT_IID_STR "f9b9e1cf-cb63-47a1-84fb-02c4894b89a9"
#  define IHOSTNAMERESOLUTIONCONFIGURATIONCHANGEEVENT_IID { \
    0xf9b9e1cf, 0xcb63, 0x47a1, \
    { 0x84, 0xfb, 0x02, 0xc4, 0x89, 0x4b, 0x89, 0xa9 } \
}
struct IHostNameResolutionConfigurationChangeEvent_vtbl
{
    struct IEvent_vtbl ievent;

};

struct IHostNameResolutionConfigurationChangeEvent
{
    struct IHostNameResolutionConfigurationChangeEvent_vtbl *vtbl;
};
/* End of struct IHostNameResolutionConfigurationChangeEvent Declaration */



#  define NS_VIRTUALBOX_CID { \
    0xB1A7A4F2, 0x47B9, 0x4A1E, \
    { 0x82, 0xB2, 0x07, 0xCC, 0xD5, 0x32, 0x3C, 0x3F } \
}
#  define NS_VIRTUALBOX_CONTRACTID "@virtualbox.org/VirtualBox;1"
/* for compatibility with Win32 */
#  define CLSID_VirtualBox (nsCID) NS_VIRTUALBOX_CID



#  define NS_VIRTUALBOXCLIENT_CID { \
    0xdd3fc71d, 0x26c0, 0x4fe1, \
    { 0xbf, 0x6f, 0x67, 0xf6, 0x33, 0x26, 0x5b, 0xba } \
}
#  define NS_VIRTUALBOXCLIENT_CONTRACTID "@virtualbox.org/VirtualBoxClient;1"
/* for compatibility with Win32 */
#  define CLSID_VirtualBoxClient (nsCID) NS_VIRTUALBOXCLIENT_CID



#  define NS_SESSION_CID { \
    0x3C02F46D, 0xC9D2, 0x4F11, \
    { 0xA3, 0x84, 0x53, 0xF0, 0xCF, 0x91, 0x72, 0x14 } \
}
#  define NS_SESSION_CONTRACTID "@virtualbox.org/Session;1"
/* for compatibility with Win32 */
#  define CLSID_Session (nsCID) NS_SESSION_CID



# endif /* !__cplusplus */

# ifdef IN_VBOXXPCOMC
#  define VBOXXPCOMC_DECL(type)  PR_EXPORT(type)
# else
#  define VBOXXPCOMC_DECL(type)  PR_IMPORT(type)
# endif

# ifdef __cplusplus
extern "C" {
# endif


/**
 * Function table for dynamic linking.
 * Use VBoxGetFunctions() to obtain the pointer to it.
 */
typedef struct VBOXXPCOMC
{
    /** The size of the structure. */
    unsigned cb;
    /** The structure version. */
    unsigned uVersion;

    /** Gets the VirtualBox version, major * 1000000 + minor * 1000 + patch. */
    unsigned int (*pfnGetVersion)(void);

    /** Gets the VirtualBox API version, major * 1000 + minor, e.g. 4003. */
    unsigned int (*pfnGetAPIVersion)(void);

    /**
     * New and preferred way to initialize the C bindings for an API client.
     *
     * This way is much more flexible, as it can easily handle multiple
     * sessions (important with more complicated API clients, including
     * multithreaded ones), and even VBoxSVC crashes can be detected and
     * processed appropriately by listening for events from the associated
     * event source in VirtualBoxClient. It is completely up to the client
     * to decide what to do (terminate or continue after getting new
     * object references to server-side objects). Must be called in the
     * primary thread of the client, later API use can be done in any
     * thread.
     *
     * Note that the returned reference is owned by the caller, and thus it's
     * the caller's responsibility to handle the reference count appropriately.
     *
     * @param pszVirtualBoxClientIID    pass IVIRTUALBOXCLIENT_IID_STR
     * @param ppVirtualBoxClient        output parameter for VirtualBoxClient
     *              reference, handled as usual with XPCOM.
     * @returns XPCOM error code
     */
    nsresult (*pfnClientInitialize)(const char *pszVirtualBoxClientIID,
                                    IVirtualBoxClient **ppVirtualBoxClient);
    /**
     * Uninitialize the C bindings for an API client.
     *
     * Should be called when the API client is about to terminate and does
     * not want to use the C bindings any more. It will invalidate all
     * object references. It is possible, however, to change one's mind,
     * and call pfnClientInitialize again to continue using the API, as long
     * as none of the object references from before the re-initialization
     * are used. Must be called from the primary thread of the client.
     */
    void (*pfnClientUninitialize)(void);

    /**
     * Deprecated way to initialize the C bindings and getting important
     * object references. Kept for backwards compatibility.
     *
     * If any returned reference is NULL then the initialization failed.
     * Note that the returned references are owned by the C bindings. The
     * number of calls to Release in the client code must match the number
     * of calls to AddRef, and additionally at no point in time there can
     * be more Release calls than AddRef calls.
     *
     * @param pszVirtualBoxIID      pass IVIRTUALBOX_IID_STR
     * @param ppVirtualBox          output parameter for VirtualBox reference,
     *          owned by C bindings
     * @param pszSessionIID         pass ISESSION_IID_STR
     * @param ppSession             output parameter for Session reference,
     *          owned by C bindings
     */
    void  (*pfnComInitialize)(const char *pszVirtualBoxIID,
                              IVirtualBox **ppVirtualBox,
                              const char *pszSessionIID,
                              ISession **ppSession);
    /**
     * Deprecated way to uninitialize the C bindings for an API client.
     * Kept for backwards compatibility and must be used if the C bindings
     * were initialized using pfnComInitialize. */
    void (*pfnComUninitialize)(void);

    /**
     * Free memory managed by XPCOM.
     *
     * @param pv        pointer to memory block to be freed
     */
    void  (*pfnComUnallocMem)(void *pv);

    /**
     * Convert string from UTF-16 encoding to UTF-8 encoding.
     *
     * @param pwszString    input string
     * @param ppszString    output string
     * @returns IPRT status code
     */
    int   (*pfnUtf16ToUtf8)(const PRUnichar *pwszString, char **ppszString);
    /**
     * Convert string from UTF-8 encoding to UTF-16 encoding.
     *
     * @param pszString     input string
     * @param ppwszString   output string
     * @returns IPRT status code
     */
    int   (*pfnUtf8ToUtf16)(const char *pszString, PRUnichar **ppwszString);
    /**
     * Free memory returned by pfnUtf16ToUtf8. Do not use for anything else.
     *
     * @param pszString     string to be freed.
     */
    void  (*pfnUtf8Free)(char *pszString);
    /**
     * Free memory returned by pfnUtf8ToUtf16. Do not use for anything else.
     *
     * @param pwszString    string to be freed.
     */
    void  (*pfnUtf16Free)(PRUnichar *pwszString);

    /**
     * Get main XPCOM event queue.
     *
     * @param ppEventQueue      output parameter for nsIEventQueue reference,
     *              owned by C bindings.
     */
    void  (*pfnGetEventQueue)(nsIEventQueue **ppEventQueue);

    /**
     * Get current XPCOM exception.
     *
     * @param ppException       output parameter for nsIException reference,
     *              may be @c NULL if no exception object has been created by
     *              a previous XPCOM call.
     * @returns XPCOM error code
     */
    nsresult (*pfnGetException)(nsIException **ppException);
    /**
     * Clears current XPCOM exception.
     *
     * @returns XPCOM error code
     */
    nsresult (*pfnClearException)(void);

    /** Tail version, same as uVersion. */
    unsigned uEndVersion;
} VBOXXPCOMC;
/** Pointer to a const VBoxXPCOMC function table. */
typedef VBOXXPCOMC const *PCVBOXXPCOM;

/** The current interface version.
 * For use with VBoxGetXPCOMCFunctions and to be found in
 * VBOXXPCOMC::uVersion. */
# define VBOX_XPCOMC_VERSION     0x00030000U

VBOXXPCOMC_DECL(PCVBOXXPCOM) VBoxGetXPCOMCFunctions(unsigned uVersion);
/** Typedef for VBoxGetXPCOMCFunctions. */
typedef PCVBOXXPCOM (*PFNVBOXGETXPCOMCFUNCTIONS)(unsigned uVersion);

/** The symbol name of VBoxGetXPCOMCFunctions. */
# if defined(__OS2__)
#  define VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME   "_VBoxGetXPCOMCFunctions"
# else
#  define VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME   "VBoxGetXPCOMCFunctions"
# endif


# ifdef __cplusplus
}
# endif

#endif /* !___VirtualBox_CXPCOM_h */
