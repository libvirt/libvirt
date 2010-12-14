/*
 * Libvirt notice: this file is derived from the VirtualBox SDK, with
 * libvirt edits; do not regenerate in the context of libvirt.
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
 * These files were originally triple-licensed (MPL/GPL2/LGPL2.1). Sun
 * elects to distribute this derived work under the LGPL2.1 only.
 */

/*
 * Copyright (C) 2008-2009 Sun Microsystems, Inc.
 *
 * This file is part of a free software library; you can redistribute
 * it and/or modify it under the terms of the GNU Lesser General
 * Public License version 2.1 as published by the Free Software
 * Foundation and shipped in the "COPYING" file with this library.
 * The library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY of any kind.
 *
 * Sun LGPL Disclaimer: For the avoidance of doubt, except that if
 * any license choice other than GPL or LGPL is available it will
 * apply instead, Sun elects to use only the Lesser General Public
 * License version 2.1 (LGPLv2) at this time for any software where
 * a choice of LGPL license versions is made available with the
 * language indicating that LGPLv2 or any later version may be used,
 * or where a choice of which version of the LGPL is applied is
 * otherwise unspecified.
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa
 * Clara, CA 95054 USA or visit http://www.sun.com if you need
 * additional information or have any questions.
 */

#ifndef ___VirtualBox_CXPCOM_h
# define ___VirtualBox_CXPCOM_h

# ifdef __cplusplus
#  include "VirtualBox_XPCOM.h"
# else /* !__cplusplus */

#  include <stddef.h>
#  include "wchar.h"

#  ifdef WIN32
#   define PR_COM_METHOD __stdcall
#  else
#   define PR_COM_METHOD
#  endif

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
  nsresult PR_COM_METHOD (*QueryInterface)(nsISupports *pThis, const nsID *iid, void **resultp);
  /**
   * Increases the reference count for this interface.
   * The associated instance will not be deleted unless
   * the reference count is returned to zero.
   *
   * @return The resulting reference count.
   */
  nsresult PR_COM_METHOD (*AddRef)(nsISupports *pThis);

  /**
   * Decreases the reference count for this interface.
   * Generally, if the reference count returns to zero,
   * the associated instance is deleted.
   *
   * @return The resulting reference count.
   */
  nsresult PR_COM_METHOD (*Release)(nsISupports *pThis);

#  ifdef WIN32
  /* The MSCOM implementation has some additional methods here.
   * So add them here to get correct binary layout of the object.
   * In API version 3.x this affects all types. */
  nsresult PR_COM_METHOD (*GetTypeInfoCount)(nsISupports *pThis);
  nsresult PR_COM_METHOD (*GetTypeInfo)(nsISupports *pThis);
  nsresult PR_COM_METHOD (*GetIDsOfNames)(nsISupports *pThis);
  nsresult PR_COM_METHOD (*Invoke)(nsISupports *pThis);
#  endif
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
  nsresult PR_COM_METHOD (*GetMessage)(nsIException *pThis, PRUnichar * *aMessage);

  /* readonly attribute nsresult PR_COM_METHOD (*result; */
  nsresult PR_COM_METHOD (*GetResult)(nsIException *pThis, nsresult *aResult);

  /* readonly attribute string name; */
  nsresult PR_COM_METHOD (*GetName)(nsIException *pThis, PRUnichar * *aName);

  /* readonly attribute string filename; */
  nsresult PR_COM_METHOD (*GetFilename)(nsIException *pThis, PRUnichar * *aFilename);

  /* readonly attribute PRUint32 lineNumber; */
  nsresult PR_COM_METHOD (*GetLineNumber)(nsIException *pThis, PRUint32 *aLineNumber);

  /* readonly attribute PRUint32 columnNumber; */
  nsresult PR_COM_METHOD (*GetColumnNumber)(nsIException *pThis, PRUint32 *aColumnNumber);

  /* readonly attribute nsIStackFrame location; */
  nsresult PR_COM_METHOD (*GetLocation)(nsIException *pThis, nsIStackFrame * *aLocation);

  /* readonly attribute nsIException inner; */
  nsresult PR_COM_METHOD (*GetInner)(nsIException *pThis, nsIException * *aInner);

  /* readonly attribute nsISupports data; */
  nsresult PR_COM_METHOD (*GetData)(nsIException *pThis, nsISupports * *aData);

  /* string toString (); */
  nsresult PR_COM_METHOD (*ToString)(nsIException *pThis, PRUnichar **_retval);
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
  nsresult PR_COM_METHOD (*GetLanguage)(nsIStackFrame *pThis, PRUint32 *aLanguage);

  /* readonly attribute string languageName; */
  nsresult PR_COM_METHOD (*GetLanguageName)(nsIStackFrame *pThis, PRUnichar * *aLanguageName);

  /* readonly attribute string filename; */
  nsresult PR_COM_METHOD (*GetFilename)(nsIStackFrame *pThis, PRUnichar * *aFilename);

  /* readonly attribute string name; */
  nsresult PR_COM_METHOD (*GetName)(nsIStackFrame *pThis, PRUnichar * *aName);

  /* readonly attribute PRInt32 lineNumber; */
  nsresult PR_COM_METHOD (*GetLineNumber)(nsIStackFrame *pThis, PRInt32 *aLineNumber);

  /* readonly attribute string sourceLine; */
  nsresult PR_COM_METHOD (*GetSourceLine)(nsIStackFrame *pThis, PRUnichar * *aSourceLine);

  /* readonly attribute nsIStackFrame caller; */
  nsresult PR_COM_METHOD (*GetCaller)(nsIStackFrame *pThis, nsIStackFrame * *aCaller);

  /* string toString (); */
  nsresult PR_COM_METHOD (*ToString)(nsIStackFrame *pThis, PRUnichar **_retval);
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

    nsresult PR_COM_METHOD (*PostEvent)(nsIEventTarget *pThis, PLEvent * aEvent);

    nsresult PR_COM_METHOD (*IsOnCurrentThread)(nsIEventTarget *pThis, PRBool *_retval);

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

    nsresult PR_COM_METHOD (*InitEvent)(nsIEventQueue *pThis, PLEvent * aEvent, void * owner, PLHandleEventProc handler, PLDestroyEventProc destructor);

    nsresult PR_COM_METHOD (*PostSynchronousEvent)(nsIEventQueue *pThis, PLEvent * aEvent, void * *aResult);

    nsresult PR_COM_METHOD (*PendingEvents)(nsIEventQueue *pThis, PRBool *_retval);

    nsresult PR_COM_METHOD (*ProcessPendingEvents)(nsIEventQueue *pThis);

    nsresult PR_COM_METHOD (*EventLoop)(nsIEventQueue *pThis);

    nsresult PR_COM_METHOD (*EventAvailable)(nsIEventQueue *pThis, PRBool *aResult);

    nsresult PR_COM_METHOD (*GetEvent)(nsIEventQueue *pThis, PLEvent * *_retval);

    nsresult PR_COM_METHOD (*HandleEvent)(nsIEventQueue *pThis, PLEvent * aEvent);

    nsresult PR_COM_METHOD (*WaitForEvent)(nsIEventQueue *pThis, PLEvent * *_retval);

    PRInt32 (*GetEventQueueSelectFD)(nsIEventQueue *pThis);

    nsresult PR_COM_METHOD (*Init)(nsIEventQueue *pThis, PRBool aNative);

    nsresult PR_COM_METHOD (*InitFromPRThread)(nsIEventQueue *pThis, PRThread * thread, PRBool aNative);

    nsresult PR_COM_METHOD (*InitFromPLQueue)(nsIEventQueue *pThis, PLEventQueue * aQueue);

    nsresult PR_COM_METHOD (*EnterMonitor)(nsIEventQueue *pThis);

    nsresult PR_COM_METHOD (*ExitMonitor)(nsIEventQueue *pThis);

    nsresult PR_COM_METHOD (*RevokeEvents)(nsIEventQueue *pThis, void * owner);

    nsresult PR_COM_METHOD (*GetPLEventQueue)(nsIEventQueue *pThis, PLEventQueue * *_retval);

    nsresult PR_COM_METHOD (*IsQueueNative)(nsIEventQueue *pThis, PRBool *_retval);

    nsresult PR_COM_METHOD (*StopAcceptingEvents)(nsIEventQueue *pThis);

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
struct ILocalOwner;
struct IVirtualBoxCallback;
struct IDHCPServer;
struct IVirtualBox;
struct IVFSExplorer;
struct IAppliance;
struct IVirtualSystemDescription;
struct IInternalMachineControl;
struct IBIOSSettings;
struct IMachine;
struct IConsoleCallback;
struct IRemoteDisplayInfo;
struct IConsole;
struct IHostNetworkInterface;
struct IHost;
struct ISystemProperties;
struct IGuestOSType;
struct IGuest;
struct IProgress;
struct ISnapshot;
struct IMediumAttachment;
struct IMedium;
struct IMediumFormat;
struct IKeyboard;
struct IMouse;
struct IFramebuffer;
struct IFramebufferOverlay;
struct IDisplay;
struct INetworkAdapter;
struct ISerialPort;
struct IParallelPort;
struct IMachineDebugger;
struct IUSBController;
struct IUSBDevice;
struct IUSBDeviceFilter;
struct IHostUSBDevice;
struct IHostUSBDeviceFilter;
struct IAudioAdapter;
struct IVRDPServer;
struct ISharedFolder;
struct IInternalSessionControl;
struct ISession;
struct IStorageController;
struct IManagedObjectRef;
struct IWebsessionManager;
struct IPerformanceMetric;
struct IPerformanceCollector;

typedef struct IVirtualBoxErrorInfo IVirtualBoxErrorInfo;
typedef struct ILocalOwner ILocalOwner;
typedef struct IVirtualBoxCallback IVirtualBoxCallback;
typedef struct IDHCPServer IDHCPServer;
typedef struct IVirtualBox IVirtualBox;
typedef struct IVFSExplorer IVFSExplorer;
typedef struct IAppliance IAppliance;
typedef struct IVirtualSystemDescription IVirtualSystemDescription;
typedef struct IInternalMachineControl IInternalMachineControl;
typedef struct IBIOSSettings IBIOSSettings;
typedef struct IMachine IMachine;
typedef struct IConsoleCallback IConsoleCallback;
typedef struct IRemoteDisplayInfo IRemoteDisplayInfo;
typedef struct IConsole IConsole;
typedef struct IHostNetworkInterface IHostNetworkInterface;
typedef struct IHost IHost;
typedef struct ISystemProperties ISystemProperties;
typedef struct IGuestOSType IGuestOSType;
typedef struct IGuest IGuest;
typedef struct IProgress IProgress;
typedef struct ISnapshot ISnapshot;
typedef struct IMediumAttachment IMediumAttachment;
typedef struct IMedium IMedium;
typedef struct IMediumFormat IMediumFormat;
typedef struct IKeyboard IKeyboard;
typedef struct IMouse IMouse;
typedef struct IFramebuffer IFramebuffer;
typedef struct IFramebufferOverlay IFramebufferOverlay;
typedef struct IDisplay IDisplay;
typedef struct INetworkAdapter INetworkAdapter;
typedef struct ISerialPort ISerialPort;
typedef struct IParallelPort IParallelPort;
typedef struct IMachineDebugger IMachineDebugger;
typedef struct IUSBController IUSBController;
typedef struct IUSBDevice IUSBDevice;
typedef struct IUSBDeviceFilter IUSBDeviceFilter;
typedef struct IHostUSBDevice IHostUSBDevice;
typedef struct IHostUSBDeviceFilter IHostUSBDeviceFilter;
typedef struct IAudioAdapter IAudioAdapter;
typedef struct IVRDPServer IVRDPServer;
typedef struct ISharedFolder ISharedFolder;
typedef struct IInternalSessionControl IInternalSessionControl;
typedef struct ISession ISession;
typedef struct IStorageController IStorageController;
typedef struct IManagedObjectRef IManagedObjectRef;
typedef struct IWebsessionManager IWebsessionManager;
typedef struct IPerformanceMetric IPerformanceMetric;
typedef struct IPerformanceCollector IPerformanceCollector;

/* Start of enum SettingsVersion Declaration */
#  define SETTINGSVERSION_IID_STR "52bd6f5f-1adb-4493-975d-581a9c4b803f"
#  define SETTINGSVERSION_IID { \
    0x52bd6f5f, 0x1adb, 0x4493, \
    { 0x97, 0x5d, 0x58, 0x1a, 0x9c, 0x4b, 0x80, 0x3f } \
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
    SettingsVersion_Future = 12
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
#  define MACHINESTATE_IID_STR "36518cf6-cdf0-4d0d-ad2a-5ee9c60c7494"
#  define MACHINESTATE_IID { \
    0x36518cf6, 0xcdf0, 0x4d0d, \
    { 0xad, 0x2a, 0x5e, 0xe9, 0xc6, 0x0c, 0x74, 0x94 } \
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
    MachineState_RestoringSnapshot = 16,
    MachineState_DeletingSnapshot = 17,
    MachineState_SettingUp = 18,
    MachineState_FirstOnline = 5,
    MachineState_LastOnline = 13,
    MachineState_FirstTransient = 8,
    MachineState_LastTransient = 18
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
    SessionState_Closed = 1,
    SessionState_Open = 2,
    SessionState_Spawning = 3,
    SessionState_Closing = 4
};
/* End of enum SessionState Declaration */


/* Start of enum CpuPropertyType Declaration */
#  define CPUPROPERTYTYPE_IID_STR "af7bb668-eeb1-4404-b77f-a114b30c92d6"
#  define CPUPROPERTYTYPE_IID { \
    0xaf7bb668, 0xeeb1, 0x4404, \
    { 0xb7, 0x7f, 0xa1, 0x14, 0xb3, 0x0c, 0x92, 0xd6 } \
}
enum CpuPropertyType
{
    CpuPropertyType_Null = 0,
    CpuPropertyType_PAE = 1,
    CpuPropertyType_Synthetic = 2
};
/* End of enum CpuPropertyType Declaration */


/* Start of enum HWVirtExPropertyType Declaration */
#  define HWVIRTEXPROPERTYTYPE_IID_STR "ce81dfdd-d2b8-4a90-bbea-40ee8b7ffcee"
#  define HWVIRTEXPROPERTYTYPE_IID { \
    0xce81dfdd, 0xd2b8, 0x4a90, \
    { 0xbb, 0xea, 0x40, 0xee, 0x8b, 0x7f, 0xfc, 0xee } \
}
enum HWVirtExPropertyType
{
    HWVirtExPropertyType_Null = 0,
    HWVirtExPropertyType_Enabled = 1,
    HWVirtExPropertyType_Exclusive = 2,
    HWVirtExPropertyType_VPID = 3,
    HWVirtExPropertyType_NestedPaging = 4
};
/* End of enum HWVirtExPropertyType Declaration */


/* Start of enum SessionType Declaration */
#  define SESSIONTYPE_IID_STR "A13C02CB-0C2C-421E-8317-AC0E8AAA153A"
#  define SESSIONTYPE_IID { \
    0xA13C02CB, 0x0C2C, 0x421E, \
    { 0x83, 0x17, 0xAC, 0x0E, 0x8A, 0xAA, 0x15, 0x3A } \
}
enum SessionType
{
    SessionType_Null = 0,
    SessionType_Direct = 1,
    SessionType_Remote = 2,
    SessionType_Existing = 3
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


/* Start of enum GuestStatisticType Declaration */
#  define GUESTSTATISTICTYPE_IID_STR "aa7c1d71-aafe-47a8-9608-27d2d337cf55"
#  define GUESTSTATISTICTYPE_IID { \
    0xaa7c1d71, 0xaafe, 0x47a8, \
    { 0x96, 0x08, 0x27, 0xd2, 0xd3, 0x37, 0xcf, 0x55 } \
}
enum GuestStatisticType
{
    GuestStatisticType_CPULoad_Idle = 0,
    GuestStatisticType_CPULoad_Kernel = 1,
    GuestStatisticType_CPULoad_User = 2,
    GuestStatisticType_Threads = 3,
    GuestStatisticType_Processes = 4,
    GuestStatisticType_Handles = 5,
    GuestStatisticType_MemoryLoad = 6,
    GuestStatisticType_PhysMemTotal = 7,
    GuestStatisticType_PhysMemAvailable = 8,
    GuestStatisticType_PhysMemBalloon = 9,
    GuestStatisticType_MemCommitTotal = 10,
    GuestStatisticType_MemKernelTotal = 11,
    GuestStatisticType_MemKernelPaged = 12,
    GuestStatisticType_MemKernelNonpaged = 13,
    GuestStatisticType_MemSystemCache = 14,
    GuestStatisticType_PageFileSize = 15,
    GuestStatisticType_SampleNumber = 16,
    GuestStatisticType_MaxVal = 17
};
/* End of enum GuestStatisticType Declaration */


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


/* Start of enum VirtualSystemDescriptionType Declaration */
#  define VIRTUALSYSTEMDESCRIPTIONTYPE_IID_STR "aacc58de-5b45-4f82-ae2e-dd9a824fc3b5"
#  define VIRTUALSYSTEMDESCRIPTIONTYPE_IID { \
    0xaacc58de, 0x5b45, 0x4f82, \
    { 0xae, 0x2e, 0xdd, 0x9a, 0x82, 0x4f, 0xc3, 0xb5 } \
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
    VirtualSystemDescriptionType_HardDiskImage = 17,
    VirtualSystemDescriptionType_Floppy = 18,
    VirtualSystemDescriptionType_CDROM = 19,
    VirtualSystemDescriptionType_NetworkAdapter = 20,
    VirtualSystemDescriptionType_USBController = 21,
    VirtualSystemDescriptionType_SoundCard = 22
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
#  define MEDIUMTYPE_IID_STR "11f6f7a5-0327-409a-9d42-7db6a0cec578"
#  define MEDIUMTYPE_IID { \
    0x11f6f7a5, 0x0327, 0x409a, \
    { 0x9d, 0x42, 0x7d, 0xb6, 0xa0, 0xce, 0xc5, 0x78 } \
}
enum MediumType
{
    MediumType_Normal = 0,
    MediumType_Immutable = 1,
    MediumType_Writethrough = 2
};
/* End of enum MediumType Declaration */


/* Start of enum MediumVariant Declaration */
#  define MEDIUMVARIANT_IID_STR "584ea502-143b-4ab0-ad14-d1028fdf0316"
#  define MEDIUMVARIANT_IID { \
    0x584ea502, 0x143b, 0x4ab0, \
    { 0xad, 0x14, 0xd1, 0x02, 0x8f, 0xdf, 0x03, 0x16 } \
}
enum MediumVariant
{
    MediumVariant_Standard = 0,
    MediumVariant_VmdkSplit2G = 0x01,
    MediumVariant_VmdkStreamOptimized = 0x04,
    MediumVariant_VmdkESX = 0x08,
    MediumVariant_Fixed = 0x10000,
    MediumVariant_Diff = 0x20000
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
#  define MEDIUMFORMATCAPABILITIES_IID_STR "70fcf810-99e8-4edc-aee4-7f51d489e657"
#  define MEDIUMFORMATCAPABILITIES_IID { \
    0x70fcf810, 0x99e8, 0x4edc, \
    { 0xae, 0xe4, 0x7f, 0x51, 0xd4, 0x89, 0xe6, 0x57 } \
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
    MediumFormatCapabilities_CapabilityMask = 0xFF
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
#  define NETWORKATTACHMENTTYPE_IID_STR "44bce1ee-99f7-4e8e-89fc-80597fd9eeaf"
#  define NETWORKATTACHMENTTYPE_IID { \
    0x44bce1ee, 0x99f7, 0x4e8e, \
    { 0x89, 0xfc, 0x80, 0x59, 0x7f, 0xd9, 0xee, 0xaf } \
}
enum NetworkAttachmentType
{
    NetworkAttachmentType_Null = 0,
    NetworkAttachmentType_NAT = 1,
    NetworkAttachmentType_Bridged = 2,
    NetworkAttachmentType_Internal = 3,
    NetworkAttachmentType_HostOnly = 4
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
    AudioControllerType_SB16 = 1
};
/* End of enum AudioControllerType Declaration */


/* Start of enum VRDPAuthType Declaration */
#  define VRDPAUTHTYPE_IID_STR "3d91887a-b67f-4b33-85bf-2da7ab1ea83a"
#  define VRDPAUTHTYPE_IID { \
    0x3d91887a, 0xb67f, 0x4b33, \
    { 0x85, 0xbf, 0x2d, 0xa7, 0xab, 0x1e, 0xa8, 0x3a } \
}
enum VRDPAuthType
{
    VRDPAuthType_Null = 0,
    VRDPAuthType_External = 1,
    VRDPAuthType_Guest = 2
};
/* End of enum VRDPAuthType Declaration */


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
    StorageBus_Floppy = 4
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
    StorageControllerType_I82078 = 7
};
/* End of enum StorageControllerType Declaration */


/* Start of struct IVirtualBoxErrorInfo Declaration */
#  define IVIRTUALBOXERRORINFO_IID_STR "4b86d186-407e-4f9e-8be8-e50061be8725"
#  define IVIRTUALBOXERRORINFO_IID { \
    0x4b86d186, 0x407e, 0x4f9e, \
    { 0x8b, 0xe8, 0xe5, 0x00, 0x61, 0xbe, 0x87, 0x25 } \
}
struct IVirtualBoxErrorInfo_vtbl
{
    struct nsIException_vtbl nsiexception;

    nsresult PR_COM_METHOD (*GetResultCode)(IVirtualBoxErrorInfo *pThis, PRInt32 *resultCode);

    nsresult PR_COM_METHOD (*GetInterfaceID)(IVirtualBoxErrorInfo *pThis, PRUnichar * *interfaceID);

    nsresult PR_COM_METHOD (*GetComponent)(IVirtualBoxErrorInfo *pThis, PRUnichar * *component);

    nsresult PR_COM_METHOD (*GetText)(IVirtualBoxErrorInfo *pThis, PRUnichar * *text);

    nsresult PR_COM_METHOD (*GetNext)(IVirtualBoxErrorInfo *pThis, IVirtualBoxErrorInfo * *next);

};

struct IVirtualBoxErrorInfo
{
    struct IVirtualBoxErrorInfo_vtbl *vtbl;
};
/* End of struct IVirtualBoxErrorInfo Declaration */


/* Start of struct ILocalOwner Declaration */
#  define ILOCALOWNER_IID_STR "308FF42A-DC45-49D4-A950-B1EEE5E00BB5"
#  define ILOCALOWNER_IID { \
    0x308FF42A, 0xDC45, 0x49D4, \
    { 0xA9, 0x50, 0xB1, 0xEE, 0xE5, 0xE0, 0x0B, 0xB5 } \
}
struct ILocalOwner_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*SetLocalObject)(
        ILocalOwner *pThis,
        nsISupports * object
    );

};

struct ILocalOwner
{
    struct ILocalOwner_vtbl *vtbl;
};
/* End of struct ILocalOwner Declaration */


/* Start of struct IVirtualBoxCallback Declaration */
#  define IVIRTUALBOXCALLBACK_IID_STR "9a65adf2-3ee6-406b-bca2-2b1fa05f0d0b"
#  define IVIRTUALBOXCALLBACK_IID { \
    0x9a65adf2, 0x3ee6, 0x406b, \
    { 0xbc, 0xa2, 0x2b, 0x1f, 0xa0, 0x5f, 0x0d, 0x0b } \
}
struct IVirtualBoxCallback_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*OnMachineStateChange)(
        IVirtualBoxCallback *pThis,
        PRUnichar * machineId,
        PRUint32 state
    );

    nsresult PR_COM_METHOD (*OnMachineDataChange)(
        IVirtualBoxCallback *pThis,
        PRUnichar * machineId
    );

    nsresult PR_COM_METHOD (*OnExtraDataCanChange)(
        IVirtualBoxCallback *pThis,
        PRUnichar * machineId,
        PRUnichar * key,
        PRUnichar * value,
        PRUnichar * * error,
        PRBool * allowChange
    );

    nsresult PR_COM_METHOD (*OnExtraDataChange)(
        IVirtualBoxCallback *pThis,
        PRUnichar * machineId,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult PR_COM_METHOD (*OnMediumRegistered)(
        IVirtualBoxCallback *pThis,
        PRUnichar * mediumId,
        PRUint32 mediumType,
        PRBool registered
    );

    nsresult PR_COM_METHOD (*OnMachineRegistered)(
        IVirtualBoxCallback *pThis,
        PRUnichar * machineId,
        PRBool registered
    );

    nsresult PR_COM_METHOD (*OnSessionStateChange)(
        IVirtualBoxCallback *pThis,
        PRUnichar * machineId,
        PRUint32 state
    );

    nsresult PR_COM_METHOD (*OnSnapshotTaken)(
        IVirtualBoxCallback *pThis,
        PRUnichar * machineId,
        PRUnichar * snapshotId
    );

    nsresult PR_COM_METHOD (*OnSnapshotDiscarded)(
        IVirtualBoxCallback *pThis,
        PRUnichar * machineId,
        PRUnichar * snapshotId
    );

    nsresult PR_COM_METHOD (*OnSnapshotChange)(
        IVirtualBoxCallback *pThis,
        PRUnichar * machineId,
        PRUnichar * snapshotId
    );

    nsresult PR_COM_METHOD (*OnGuestPropertyChange)(
        IVirtualBoxCallback *pThis,
        PRUnichar * machineId,
        PRUnichar * name,
        PRUnichar * value,
        PRUnichar * flags
    );

};

struct IVirtualBoxCallback
{
    struct IVirtualBoxCallback_vtbl *vtbl;
};
/* End of struct IVirtualBoxCallback Declaration */


/* Start of struct IDHCPServer Declaration */
#  define IDHCPSERVER_IID_STR "6cfe387c-74fb-4ca7-bff6-973bec8af7a3"
#  define IDHCPSERVER_IID { \
    0x6cfe387c, 0x74fb, 0x4ca7, \
    { 0xbf, 0xf6, 0x97, 0x3b, 0xec, 0x8a, 0xf7, 0xa3 } \
}
struct IDHCPServer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetEnabled)(IDHCPServer *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(IDHCPServer *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetIPAddress)(IDHCPServer *pThis, PRUnichar * *IPAddress);

    nsresult PR_COM_METHOD (*GetNetworkMask)(IDHCPServer *pThis, PRUnichar * *networkMask);

    nsresult PR_COM_METHOD (*GetNetworkName)(IDHCPServer *pThis, PRUnichar * *networkName);

    nsresult PR_COM_METHOD (*GetLowerIP)(IDHCPServer *pThis, PRUnichar * *lowerIP);

    nsresult PR_COM_METHOD (*GetUpperIP)(IDHCPServer *pThis, PRUnichar * *upperIP);

    nsresult PR_COM_METHOD (*SetConfiguration)(
        IDHCPServer *pThis,
        PRUnichar * IPAddress,
        PRUnichar * networkMask,
        PRUnichar * FromIPAddress,
        PRUnichar * ToIPAddress
    );

    nsresult PR_COM_METHOD (*Start)(
        IDHCPServer *pThis,
        PRUnichar * networkName,
        PRUnichar * trunkName,
        PRUnichar * trunkType
    );

    nsresult PR_COM_METHOD (*Stop)(IDHCPServer *pThis );

};

struct IDHCPServer
{
    struct IDHCPServer_vtbl *vtbl;
};
/* End of struct IDHCPServer Declaration */


/* Start of struct IVirtualBox Declaration */
#  define IVIRTUALBOX_IID_STR "2158464a-f706-414b-a8c4-fb589dfc6b62"
#  define IVIRTUALBOX_IID { \
    0x2158464a, 0xf706, 0x414b, \
    { 0xa8, 0xc4, 0xfb, 0x58, 0x9d, 0xfc, 0x6b, 0x62 } \
}
struct IVirtualBox_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetVersion)(IVirtualBox *pThis, PRUnichar * *version);

    nsresult PR_COM_METHOD (*GetRevision)(IVirtualBox *pThis, PRUint32 *revision);

    nsresult PR_COM_METHOD (*GetPackageType)(IVirtualBox *pThis, PRUnichar * *packageType);

    nsresult PR_COM_METHOD (*GetHomeFolder)(IVirtualBox *pThis, PRUnichar * *homeFolder);

    nsresult PR_COM_METHOD (*GetSettingsFilePath)(IVirtualBox *pThis, PRUnichar * *settingsFilePath);

    nsresult PR_COM_METHOD (*GetHost)(IVirtualBox *pThis, IHost * *host);

    nsresult PR_COM_METHOD (*GetSystemProperties)(IVirtualBox *pThis, ISystemProperties * *systemProperties);

    nsresult PR_COM_METHOD (*GetMachines)(IVirtualBox *pThis, PRUint32 *machinesSize, IMachine * **machines);

    nsresult PR_COM_METHOD (*GetHardDisks)(IVirtualBox *pThis, PRUint32 *hardDisksSize, IMedium * **hardDisks);

    nsresult PR_COM_METHOD (*GetDVDImages)(IVirtualBox *pThis, PRUint32 *DVDImagesSize, IMedium * **DVDImages);

    nsresult PR_COM_METHOD (*GetFloppyImages)(IVirtualBox *pThis, PRUint32 *floppyImagesSize, IMedium * **floppyImages);

    nsresult PR_COM_METHOD (*GetProgressOperations)(IVirtualBox *pThis, PRUint32 *progressOperationsSize, IProgress * **progressOperations);

    nsresult PR_COM_METHOD (*GetGuestOSTypes)(IVirtualBox *pThis, PRUint32 *guestOSTypesSize, IGuestOSType * **guestOSTypes);

    nsresult PR_COM_METHOD (*GetSharedFolders)(IVirtualBox *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult PR_COM_METHOD (*GetPerformanceCollector)(IVirtualBox *pThis, IPerformanceCollector * *performanceCollector);

    nsresult PR_COM_METHOD (*GetDHCPServers)(IVirtualBox *pThis, PRUint32 *DHCPServersSize, IDHCPServer * **DHCPServers);

    nsresult PR_COM_METHOD (*CreateMachine)(
        IVirtualBox *pThis,
        PRUnichar * name,
        PRUnichar * osTypeId,
        PRUnichar * baseFolder,
        PRUnichar * id,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*CreateLegacyMachine)(
        IVirtualBox *pThis,
        PRUnichar * name,
        PRUnichar * osTypeId,
        PRUnichar * settingsFile,
        PRUnichar * id,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*OpenMachine)(
        IVirtualBox *pThis,
        PRUnichar * settingsFile,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*RegisterMachine)(
        IVirtualBox *pThis,
        IMachine * machine
    );

    nsresult PR_COM_METHOD (*GetMachine)(
        IVirtualBox *pThis,
        PRUnichar * id,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*FindMachine)(
        IVirtualBox *pThis,
        PRUnichar * name,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*UnregisterMachine)(
        IVirtualBox *pThis,
        PRUnichar * id,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*CreateAppliance)(
        IVirtualBox *pThis,
        IAppliance * * appliance
    );

    nsresult PR_COM_METHOD (*CreateHardDisk)(
        IVirtualBox *pThis,
        PRUnichar * format,
        PRUnichar * location,
        IMedium * * medium
    );

    nsresult PR_COM_METHOD (*OpenHardDisk)(
        IVirtualBox *pThis,
        PRUnichar * location,
        PRUint32 accessMode,
        PRBool setImageId,
        PRUnichar * imageId,
        PRBool setParentId,
        PRUnichar * parentId,
        IMedium * * medium
    );

    nsresult PR_COM_METHOD (*GetHardDisk)(
        IVirtualBox *pThis,
        PRUnichar * id,
        IMedium * * medium
    );

    nsresult PR_COM_METHOD (*FindHardDisk)(
        IVirtualBox *pThis,
        PRUnichar * location,
        IMedium * * medium
    );

    nsresult PR_COM_METHOD (*OpenDVDImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        PRUnichar * id,
        IMedium * * image
    );

    nsresult PR_COM_METHOD (*GetDVDImage)(
        IVirtualBox *pThis,
        PRUnichar * id,
        IMedium * * image
    );

    nsresult PR_COM_METHOD (*FindDVDImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        IMedium * * image
    );

    nsresult PR_COM_METHOD (*OpenFloppyImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        PRUnichar * id,
        IMedium * * image
    );

    nsresult PR_COM_METHOD (*GetFloppyImage)(
        IVirtualBox *pThis,
        PRUnichar * id,
        IMedium * * image
    );

    nsresult PR_COM_METHOD (*FindFloppyImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        IMedium * * image
    );

    nsresult PR_COM_METHOD (*GetGuestOSType)(
        IVirtualBox *pThis,
        PRUnichar * id,
        IGuestOSType * * type
    );

    nsresult PR_COM_METHOD (*CreateSharedFolder)(
        IVirtualBox *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable
    );

    nsresult PR_COM_METHOD (*RemoveSharedFolder)(
        IVirtualBox *pThis,
        PRUnichar * name
    );

    nsresult PR_COM_METHOD (*GetExtraDataKeys)(
        IVirtualBox *pThis,
        PRUint32 *valueSize,
        PRUnichar *** value
    );

    nsresult PR_COM_METHOD (*GetExtraData)(
        IVirtualBox *pThis,
        PRUnichar * key,
        PRUnichar * * value
    );

    nsresult PR_COM_METHOD (*SetExtraData)(
        IVirtualBox *pThis,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult PR_COM_METHOD (*OpenSession)(
        IVirtualBox *pThis,
        ISession * session,
        PRUnichar * machineId
    );

    nsresult PR_COM_METHOD (*OpenRemoteSession)(
        IVirtualBox *pThis,
        ISession * session,
        PRUnichar * machineId,
        PRUnichar * type,
        PRUnichar * environment,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*OpenExistingSession)(
        IVirtualBox *pThis,
        ISession * session,
        PRUnichar * machineId
    );

    nsresult PR_COM_METHOD (*RegisterCallback)(
        IVirtualBox *pThis,
        IVirtualBoxCallback * callback
    );

    nsresult PR_COM_METHOD (*UnregisterCallback)(
        IVirtualBox *pThis,
        IVirtualBoxCallback * callback
    );

    nsresult PR_COM_METHOD (*WaitForPropertyChange)(
        IVirtualBox *pThis,
        PRUnichar * what,
        PRUint32 timeout,
        PRUnichar * * changed,
        PRUnichar * * values
    );

    nsresult PR_COM_METHOD (*CreateDHCPServer)(
        IVirtualBox *pThis,
        PRUnichar * name,
        IDHCPServer * * server
    );

    nsresult PR_COM_METHOD (*FindDHCPServerByNetworkName)(
        IVirtualBox *pThis,
        PRUnichar * name,
        IDHCPServer * * server
    );

    nsresult PR_COM_METHOD (*RemoveDHCPServer)(
        IVirtualBox *pThis,
        IDHCPServer * server
    );

    nsresult PR_COM_METHOD (*CheckFirmwarePresent)(
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
#  define IVFSEXPLORER_IID_STR "2bb864a1-02a3-4474-a1d4-fb5f23b742e1"
#  define IVFSEXPLORER_IID { \
    0x2bb864a1, 0x02a3, 0x4474, \
    { 0xa1, 0xd4, 0xfb, 0x5f, 0x23, 0xb7, 0x42, 0xe1 } \
}
struct IVFSExplorer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetPath)(IVFSExplorer *pThis, PRUnichar * *path);

    nsresult PR_COM_METHOD (*GetType)(IVFSExplorer *pThis, PRUint32 *type);

    nsresult PR_COM_METHOD (*Update)(
        IVFSExplorer *pThis,
        IProgress * * aProgress
    );

    nsresult PR_COM_METHOD (*Cd)(
        IVFSExplorer *pThis,
        PRUnichar * aDir,
        IProgress * * aProgress
    );

    nsresult PR_COM_METHOD (*CdUp)(
        IVFSExplorer *pThis,
        IProgress * * aProgress
    );

    nsresult PR_COM_METHOD (*EntryList)(
        IVFSExplorer *pThis,
        PRUint32 *aNamesSize,
        PRUnichar *** aNames,
        PRUint32 *aTypesSize,
        PRUint32* aTypes
    );

    nsresult PR_COM_METHOD (*Exists)(
        IVFSExplorer *pThis,
        PRUint32 aNamesSize,
        PRUnichar ** aNames,
        PRUint32 *aExistsSize,
        PRUnichar *** aExists
    );

    nsresult PR_COM_METHOD (*Remove)(
        IVFSExplorer *pThis,
        PRUint32 aNamesSize,
        PRUnichar ** aNames,
        IProgress * * aProgress
    );

};

struct IVFSExplorer
{
    struct IVFSExplorer_vtbl *vtbl;
};
/* End of struct IVFSExplorer Declaration */


/* Start of struct IAppliance Declaration */
#  define IAPPLIANCE_IID_STR "e3ba9ab9-ac2c-4266-8bd2-91c4bf721ceb"
#  define IAPPLIANCE_IID { \
    0xe3ba9ab9, 0xac2c, 0x4266, \
    { 0x8b, 0xd2, 0x91, 0xc4, 0xbf, 0x72, 0x1c, 0xeb } \
}
struct IAppliance_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetPath)(IAppliance *pThis, PRUnichar * *path);

    nsresult PR_COM_METHOD (*GetDisks)(IAppliance *pThis, PRUint32 *disksSize, PRUnichar * **disks);

    nsresult PR_COM_METHOD (*GetVirtualSystemDescriptions)(IAppliance *pThis, PRUint32 *virtualSystemDescriptionsSize, IVirtualSystemDescription * **virtualSystemDescriptions);

    nsresult PR_COM_METHOD (*Read)(
        IAppliance *pThis,
        PRUnichar * file,
        IProgress * * aProgress
    );

    nsresult PR_COM_METHOD (*Interpret)(IAppliance *pThis );

    nsresult PR_COM_METHOD (*ImportMachines)(
        IAppliance *pThis,
        IProgress * * aProgress
    );

    nsresult PR_COM_METHOD (*CreateVFSExplorer)(
        IAppliance *pThis,
        PRUnichar * aUri,
        IVFSExplorer * * aExplorer
    );

    nsresult PR_COM_METHOD (*Write)(
        IAppliance *pThis,
        PRUnichar * format,
        PRUnichar * path,
        IProgress * * aProgress
    );

    nsresult PR_COM_METHOD (*GetWarnings)(
        IAppliance *pThis,
        PRUint32 *aWarningsSize,
        PRUnichar *** aWarnings
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

    nsresult PR_COM_METHOD (*GetCount)(IVirtualSystemDescription *pThis, PRUint32 *count);

    nsresult PR_COM_METHOD (*GetDescription)(
        IVirtualSystemDescription *pThis,
        PRUint32 *aTypesSize,
        PRUint32* aTypes,
        PRUint32 *aRefsSize,
        PRUnichar *** aRefs,
        PRUint32 *aOvfValuesSize,
        PRUnichar *** aOvfValues,
        PRUint32 *aVBoxValuesSize,
        PRUnichar *** aVBoxValues,
        PRUint32 *aExtraConfigValuesSize,
        PRUnichar *** aExtraConfigValues
    );

    nsresult PR_COM_METHOD (*GetDescriptionByType)(
        IVirtualSystemDescription *pThis,
        PRUint32 aType,
        PRUint32 *aTypesSize,
        PRUint32* aTypes,
        PRUint32 *aRefsSize,
        PRUnichar *** aRefs,
        PRUint32 *aOvfValuesSize,
        PRUnichar *** aOvfValues,
        PRUint32 *aVBoxValuesSize,
        PRUnichar *** aVBoxValues,
        PRUint32 *aExtraConfigValuesSize,
        PRUnichar *** aExtraConfigValues
    );

    nsresult PR_COM_METHOD (*GetValuesByType)(
        IVirtualSystemDescription *pThis,
        PRUint32 aType,
        PRUint32 aWhich,
        PRUint32 *aValuesSize,
        PRUnichar *** aValues
    );

    nsresult PR_COM_METHOD (*SetFinalValues)(
        IVirtualSystemDescription *pThis,
        PRUint32 aEnabledSize,
        PRBool* aEnabled,
        PRUint32 aVBoxValuesSize,
        PRUnichar ** aVBoxValues,
        PRUint32 aExtraConfigValuesSize,
        PRUnichar ** aExtraConfigValues
    );

    nsresult PR_COM_METHOD (*AddDescription)(
        IVirtualSystemDescription *pThis,
        PRUint32 aType,
        PRUnichar * aVBoxValue,
        PRUnichar * aExtraConfigValue
    );

};

struct IVirtualSystemDescription
{
    struct IVirtualSystemDescription_vtbl *vtbl;
};
/* End of struct IVirtualSystemDescription Declaration */


/* Start of struct IInternalMachineControl Declaration */
#  define IINTERNALMACHINECONTROL_IID_STR "35d8d838-d066-447d-927a-fd93afdbec90"
#  define IINTERNALMACHINECONTROL_IID { \
    0x35d8d838, 0xd066, 0x447d, \
    { 0x92, 0x7a, 0xfd, 0x93, 0xaf, 0xdb, 0xec, 0x90 } \
}
struct IInternalMachineControl_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*SetRemoveSavedState)(
        IInternalMachineControl *pThis,
        PRBool aRemove
    );

    nsresult PR_COM_METHOD (*UpdateState)(
        IInternalMachineControl *pThis,
        PRUint32 state
    );

    nsresult PR_COM_METHOD (*GetIPCId)(
        IInternalMachineControl *pThis,
        PRUnichar * * id
    );

    nsresult PR_COM_METHOD (*RunUSBDeviceFilters)(
        IInternalMachineControl *pThis,
        IUSBDevice * device,
        PRBool * matched,
        PRUint32 * maskedInterfaces
    );

    nsresult PR_COM_METHOD (*CaptureUSBDevice)(
        IInternalMachineControl *pThis,
        PRUnichar * id
    );

    nsresult PR_COM_METHOD (*DetachUSBDevice)(
        IInternalMachineControl *pThis,
        PRUnichar * id,
        PRBool done
    );

    nsresult PR_COM_METHOD (*AutoCaptureUSBDevices)(IInternalMachineControl *pThis );

    nsresult PR_COM_METHOD (*DetachAllUSBDevices)(
        IInternalMachineControl *pThis,
        PRBool done
    );

    nsresult PR_COM_METHOD (*OnSessionEnd)(
        IInternalMachineControl *pThis,
        ISession * session,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*BeginSavingState)(
        IInternalMachineControl *pThis,
        IProgress * progress,
        PRUnichar * * stateFilePath
    );

    nsresult PR_COM_METHOD (*EndSavingState)(
        IInternalMachineControl *pThis,
        PRBool success
    );

    nsresult PR_COM_METHOD (*AdoptSavedState)(
        IInternalMachineControl *pThis,
        PRUnichar * savedStateFile
    );

    nsresult PR_COM_METHOD (*BeginTakingSnapshot)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        PRUnichar * name,
        PRUnichar * description,
        IProgress * consoleProgress,
        PRBool fTakingSnapshotOnline,
        PRUnichar * * stateFilePath
    );

    nsresult PR_COM_METHOD (*EndTakingSnapshot)(
        IInternalMachineControl *pThis,
        PRBool success
    );

    nsresult PR_COM_METHOD (*DeleteSnapshot)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        PRUnichar * id,
        PRUint32 * machineState,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*RestoreSnapshot)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        ISnapshot * snapshot,
        PRUint32 * machineState,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*PullGuestProperties)(
        IInternalMachineControl *pThis,
        PRUint32 *nameSize,
        PRUnichar *** name,
        PRUint32 *valueSize,
        PRUnichar *** value,
        PRUint32 *timestampSize,
        PRUint64* timestamp,
        PRUint32 *flagsSize,
        PRUnichar *** flags
    );

    nsresult PR_COM_METHOD (*PushGuestProperties)(
        IInternalMachineControl *pThis,
        PRUint32 nameSize,
        PRUnichar ** name,
        PRUint32 valueSize,
        PRUnichar ** value,
        PRUint32 timestampSize,
        PRUint64* timestamp,
        PRUint32 flagsSize,
        PRUnichar ** flags
    );

    nsresult PR_COM_METHOD (*PushGuestProperty)(
        IInternalMachineControl *pThis,
        PRUnichar * name,
        PRUnichar * value,
        PRUint64 timestamp,
        PRUnichar * flags
    );

    nsresult PR_COM_METHOD (*LockMedia)(IInternalMachineControl *pThis );

    nsresult PR_COM_METHOD (*UnlockMedia)(IInternalMachineControl *pThis );

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

    nsresult PR_COM_METHOD (*GetLogoFadeIn)(IBIOSSettings *pThis, PRBool *logoFadeIn);
    nsresult PR_COM_METHOD (*SetLogoFadeIn)(IBIOSSettings *pThis, PRBool logoFadeIn);

    nsresult PR_COM_METHOD (*GetLogoFadeOut)(IBIOSSettings *pThis, PRBool *logoFadeOut);
    nsresult PR_COM_METHOD (*SetLogoFadeOut)(IBIOSSettings *pThis, PRBool logoFadeOut);

    nsresult PR_COM_METHOD (*GetLogoDisplayTime)(IBIOSSettings *pThis, PRUint32 *logoDisplayTime);
    nsresult PR_COM_METHOD (*SetLogoDisplayTime)(IBIOSSettings *pThis, PRUint32 logoDisplayTime);

    nsresult PR_COM_METHOD (*GetLogoImagePath)(IBIOSSettings *pThis, PRUnichar * *logoImagePath);
    nsresult PR_COM_METHOD (*SetLogoImagePath)(IBIOSSettings *pThis, PRUnichar * logoImagePath);

    nsresult PR_COM_METHOD (*GetBootMenuMode)(IBIOSSettings *pThis, PRUint32 *bootMenuMode);
    nsresult PR_COM_METHOD (*SetBootMenuMode)(IBIOSSettings *pThis, PRUint32 bootMenuMode);

    nsresult PR_COM_METHOD (*GetACPIEnabled)(IBIOSSettings *pThis, PRBool *ACPIEnabled);
    nsresult PR_COM_METHOD (*SetACPIEnabled)(IBIOSSettings *pThis, PRBool ACPIEnabled);

    nsresult PR_COM_METHOD (*GetIOAPICEnabled)(IBIOSSettings *pThis, PRBool *IOAPICEnabled);
    nsresult PR_COM_METHOD (*SetIOAPICEnabled)(IBIOSSettings *pThis, PRBool IOAPICEnabled);

    nsresult PR_COM_METHOD (*GetTimeOffset)(IBIOSSettings *pThis, PRInt64 *timeOffset);
    nsresult PR_COM_METHOD (*SetTimeOffset)(IBIOSSettings *pThis, PRInt64 timeOffset);

    nsresult PR_COM_METHOD (*GetPXEDebugEnabled)(IBIOSSettings *pThis, PRBool *PXEDebugEnabled);
    nsresult PR_COM_METHOD (*SetPXEDebugEnabled)(IBIOSSettings *pThis, PRBool PXEDebugEnabled);

};

struct IBIOSSettings
{
    struct IBIOSSettings_vtbl *vtbl;
};
/* End of struct IBIOSSettings Declaration */


/* Start of struct IMachine Declaration */
#  define IMACHINE_IID_STR "99404f50-dd10-40d3-889b-dd2f79f1e95e"
#  define IMACHINE_IID { \
    0x99404f50, 0xdd10, 0x40d3, \
    { 0x88, 0x9b, 0xdd, 0x2f, 0x79, 0xf1, 0xe9, 0x5e } \
}
struct IMachine_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetParent)(IMachine *pThis, IVirtualBox * *parent);

    nsresult PR_COM_METHOD (*GetAccessible)(IMachine *pThis, PRBool *accessible);

    nsresult PR_COM_METHOD (*GetAccessError)(IMachine *pThis, IVirtualBoxErrorInfo * *accessError);

    nsresult PR_COM_METHOD (*GetName)(IMachine *pThis, PRUnichar * *name);
    nsresult PR_COM_METHOD (*SetName)(IMachine *pThis, PRUnichar * name);

    nsresult PR_COM_METHOD (*GetDescription)(IMachine *pThis, PRUnichar * *description);
    nsresult PR_COM_METHOD (*SetDescription)(IMachine *pThis, PRUnichar * description);

    nsresult PR_COM_METHOD (*GetId)(IMachine *pThis, PRUnichar * *id);

    nsresult PR_COM_METHOD (*GetOSTypeId)(IMachine *pThis, PRUnichar * *OSTypeId);
    nsresult PR_COM_METHOD (*SetOSTypeId)(IMachine *pThis, PRUnichar * OSTypeId);

    nsresult PR_COM_METHOD (*GetHardwareVersion)(IMachine *pThis, PRUnichar * *HardwareVersion);
    nsresult PR_COM_METHOD (*SetHardwareVersion)(IMachine *pThis, PRUnichar * HardwareVersion);

    nsresult PR_COM_METHOD (*GetHardwareUUID)(IMachine *pThis, PRUnichar * *hardwareUUID);
    nsresult PR_COM_METHOD (*SetHardwareUUID)(IMachine *pThis, PRUnichar * hardwareUUID);

    nsresult PR_COM_METHOD (*GetCPUCount)(IMachine *pThis, PRUint32 *CPUCount);
    nsresult PR_COM_METHOD (*SetCPUCount)(IMachine *pThis, PRUint32 CPUCount);

    nsresult PR_COM_METHOD (*GetMemorySize)(IMachine *pThis, PRUint32 *memorySize);
    nsresult PR_COM_METHOD (*SetMemorySize)(IMachine *pThis, PRUint32 memorySize);

    nsresult PR_COM_METHOD (*GetMemoryBalloonSize)(IMachine *pThis, PRUint32 *memoryBalloonSize);
    nsresult PR_COM_METHOD (*SetMemoryBalloonSize)(IMachine *pThis, PRUint32 memoryBalloonSize);

    nsresult PR_COM_METHOD (*GetStatisticsUpdateInterval)(IMachine *pThis, PRUint32 *statisticsUpdateInterval);
    nsresult PR_COM_METHOD (*SetStatisticsUpdateInterval)(IMachine *pThis, PRUint32 statisticsUpdateInterval);

    nsresult PR_COM_METHOD (*GetVRAMSize)(IMachine *pThis, PRUint32 *VRAMSize);
    nsresult PR_COM_METHOD (*SetVRAMSize)(IMachine *pThis, PRUint32 VRAMSize);

    nsresult PR_COM_METHOD (*GetAccelerate3DEnabled)(IMachine *pThis, PRBool *accelerate3DEnabled);
    nsresult PR_COM_METHOD (*SetAccelerate3DEnabled)(IMachine *pThis, PRBool accelerate3DEnabled);

    nsresult PR_COM_METHOD (*GetAccelerate2DVideoEnabled)(IMachine *pThis, PRBool *accelerate2DVideoEnabled);
    nsresult PR_COM_METHOD (*SetAccelerate2DVideoEnabled)(IMachine *pThis, PRBool accelerate2DVideoEnabled);

    nsresult PR_COM_METHOD (*GetMonitorCount)(IMachine *pThis, PRUint32 *monitorCount);
    nsresult PR_COM_METHOD (*SetMonitorCount)(IMachine *pThis, PRUint32 monitorCount);

    nsresult PR_COM_METHOD (*GetBIOSSettings)(IMachine *pThis, IBIOSSettings * *BIOSSettings);

    nsresult PR_COM_METHOD (*GetFirmwareType)(IMachine *pThis, PRUint32 *firmwareType);
    nsresult PR_COM_METHOD (*SetFirmwareType)(IMachine *pThis, PRUint32 firmwareType);

    nsresult PR_COM_METHOD (*GetSnapshotFolder)(IMachine *pThis, PRUnichar * *snapshotFolder);
    nsresult PR_COM_METHOD (*SetSnapshotFolder)(IMachine *pThis, PRUnichar * snapshotFolder);

    nsresult PR_COM_METHOD (*GetVRDPServer)(IMachine *pThis, IVRDPServer * *VRDPServer);

    nsresult PR_COM_METHOD (*GetMediumAttachments)(IMachine *pThis, PRUint32 *mediumAttachmentsSize, IMediumAttachment * **mediumAttachments);

    nsresult PR_COM_METHOD (*GetUSBController)(IMachine *pThis, IUSBController * *USBController);

    nsresult PR_COM_METHOD (*GetAudioAdapter)(IMachine *pThis, IAudioAdapter * *audioAdapter);

    nsresult PR_COM_METHOD (*GetStorageControllers)(IMachine *pThis, PRUint32 *storageControllersSize, IStorageController * **storageControllers);

    nsresult PR_COM_METHOD (*GetSettingsFilePath)(IMachine *pThis, PRUnichar * *settingsFilePath);

    nsresult PR_COM_METHOD (*GetSettingsModified)(IMachine *pThis, PRBool *settingsModified);

    nsresult PR_COM_METHOD (*GetSessionState)(IMachine *pThis, PRUint32 *sessionState);

    nsresult PR_COM_METHOD (*GetSessionType)(IMachine *pThis, PRUnichar * *sessionType);

    nsresult PR_COM_METHOD (*GetSessionPid)(IMachine *pThis, PRUint32 *sessionPid);

    nsresult PR_COM_METHOD (*GetState)(IMachine *pThis, PRUint32 *state);

    nsresult PR_COM_METHOD (*GetLastStateChange)(IMachine *pThis, PRInt64 *lastStateChange);

    nsresult PR_COM_METHOD (*GetStateFilePath)(IMachine *pThis, PRUnichar * *stateFilePath);

    nsresult PR_COM_METHOD (*GetLogFolder)(IMachine *pThis, PRUnichar * *logFolder);

    nsresult PR_COM_METHOD (*GetCurrentSnapshot)(IMachine *pThis, ISnapshot * *currentSnapshot);

    nsresult PR_COM_METHOD (*GetSnapshotCount)(IMachine *pThis, PRUint32 *snapshotCount);

    nsresult PR_COM_METHOD (*GetCurrentStateModified)(IMachine *pThis, PRBool *currentStateModified);

    nsresult PR_COM_METHOD (*GetSharedFolders)(IMachine *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult PR_COM_METHOD (*GetClipboardMode)(IMachine *pThis, PRUint32 *clipboardMode);
    nsresult PR_COM_METHOD (*SetClipboardMode)(IMachine *pThis, PRUint32 clipboardMode);

    nsresult PR_COM_METHOD (*GetGuestPropertyNotificationPatterns)(IMachine *pThis, PRUnichar * *guestPropertyNotificationPatterns);
    nsresult PR_COM_METHOD (*SetGuestPropertyNotificationPatterns)(IMachine *pThis, PRUnichar * guestPropertyNotificationPatterns);

    nsresult PR_COM_METHOD (*GetTeleporterEnabled)(IMachine *pThis, PRBool *teleporterEnabled);
    nsresult PR_COM_METHOD (*SetTeleporterEnabled)(IMachine *pThis, PRBool teleporterEnabled);

    nsresult PR_COM_METHOD (*GetTeleporterPort)(IMachine *pThis, PRUint32 *teleporterPort);
    nsresult PR_COM_METHOD (*SetTeleporterPort)(IMachine *pThis, PRUint32 teleporterPort);

    nsresult PR_COM_METHOD (*GetTeleporterAddress)(IMachine *pThis, PRUnichar * *teleporterAddress);
    nsresult PR_COM_METHOD (*SetTeleporterAddress)(IMachine *pThis, PRUnichar * teleporterAddress);

    nsresult PR_COM_METHOD (*GetTeleporterPassword)(IMachine *pThis, PRUnichar * *teleporterPassword);
    nsresult PR_COM_METHOD (*SetTeleporterPassword)(IMachine *pThis, PRUnichar * teleporterPassword);

    nsresult PR_COM_METHOD (*SetBootOrder)(
        IMachine *pThis,
        PRUint32 position,
        PRUint32 device
    );

    nsresult PR_COM_METHOD (*GetBootOrder)(
        IMachine *pThis,
        PRUint32 position,
        PRUint32 * device
    );

    nsresult PR_COM_METHOD (*AttachDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        PRUint32 type,
        PRUnichar * id
    );

    nsresult PR_COM_METHOD (*DetachDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device
    );

    nsresult PR_COM_METHOD (*PassthroughDevice)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        PRBool passthrough
    );

    nsresult PR_COM_METHOD (*MountMedium)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        PRUnichar * medium,
        PRBool force
    );

    nsresult PR_COM_METHOD (*GetMedium)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        IMedium * * medium
    );

    nsresult PR_COM_METHOD (*GetMediumAttachmentsOfController)(
        IMachine *pThis,
        PRUnichar * name,
        PRUint32 *mediumAttachmentsSize,
        IMediumAttachment *** mediumAttachments
    );

    nsresult PR_COM_METHOD (*GetMediumAttachment)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        IMediumAttachment * * attachment
    );

    nsresult PR_COM_METHOD (*GetNetworkAdapter)(
        IMachine *pThis,
        PRUint32 slot,
        INetworkAdapter * * adapter
    );

    nsresult PR_COM_METHOD (*AddStorageController)(
        IMachine *pThis,
        PRUnichar * name,
        PRUint32 connectionType,
        IStorageController * * controller
    );

    nsresult PR_COM_METHOD (*GetStorageControllerByName)(
        IMachine *pThis,
        PRUnichar * name,
        IStorageController * * storageController
    );

    nsresult PR_COM_METHOD (*GetStorageControllerByInstance)(
        IMachine *pThis,
        PRUint32 instance,
        IStorageController * * storageController
    );

    nsresult PR_COM_METHOD (*RemoveStorageController)(
        IMachine *pThis,
        PRUnichar * name
    );

    nsresult PR_COM_METHOD (*GetSerialPort)(
        IMachine *pThis,
        PRUint32 slot,
        ISerialPort * * port
    );

    nsresult PR_COM_METHOD (*GetParallelPort)(
        IMachine *pThis,
        PRUint32 slot,
        IParallelPort * * port
    );

    nsresult PR_COM_METHOD (*GetExtraDataKeys)(
        IMachine *pThis,
        PRUint32 *valueSize,
        PRUnichar *** value
    );

    nsresult PR_COM_METHOD (*GetExtraData)(
        IMachine *pThis,
        PRUnichar * key,
        PRUnichar * * value
    );

    nsresult PR_COM_METHOD (*SetExtraData)(
        IMachine *pThis,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult PR_COM_METHOD (*GetCpuProperty)(
        IMachine *pThis,
        PRUint32 property,
        PRBool * value
    );

    nsresult PR_COM_METHOD (*SetCpuProperty)(
        IMachine *pThis,
        PRUint32 property,
        PRBool value
    );

    nsresult PR_COM_METHOD (*GetCpuIdLeaf)(
        IMachine *pThis,
        PRUint32 id,
        PRUint32 * valEax,
        PRUint32 * valEbx,
        PRUint32 * valEcx,
        PRUint32 * valEdx
    );

    nsresult PR_COM_METHOD (*SetCpuIdLeaf)(
        IMachine *pThis,
        PRUint32 id,
        PRUint32 valEax,
        PRUint32 valEbx,
        PRUint32 valEcx,
        PRUint32 valEdx
    );

    nsresult PR_COM_METHOD (*RemoveCpuIdLeaf)(
        IMachine *pThis,
        PRUint32 id
    );

    nsresult PR_COM_METHOD (*RemoveAllCpuIdLeafs)(IMachine *pThis );

    nsresult PR_COM_METHOD (*GetHWVirtExProperty)(
        IMachine *pThis,
        PRUint32 property,
        PRBool * value
    );

    nsresult PR_COM_METHOD (*SetHWVirtExProperty)(
        IMachine *pThis,
        PRUint32 property,
        PRBool value
    );

    nsresult PR_COM_METHOD (*SaveSettings)(IMachine *pThis );

    nsresult PR_COM_METHOD (*DiscardSettings)(IMachine *pThis );

    nsresult PR_COM_METHOD (*DeleteSettings)(IMachine *pThis );

    nsresult PR_COM_METHOD (*Export)(
        IMachine *pThis,
        IAppliance * aAppliance,
        IVirtualSystemDescription * * aDescription
    );

    nsresult PR_COM_METHOD (*GetSnapshot)(
        IMachine *pThis,
        PRUnichar * id,
        ISnapshot * * snapshot
    );

    nsresult PR_COM_METHOD (*FindSnapshot)(
        IMachine *pThis,
        PRUnichar * name,
        ISnapshot * * snapshot
    );

    nsresult PR_COM_METHOD (*SetCurrentSnapshot)(
        IMachine *pThis,
        PRUnichar * id
    );

    nsresult PR_COM_METHOD (*CreateSharedFolder)(
        IMachine *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable
    );

    nsresult PR_COM_METHOD (*RemoveSharedFolder)(
        IMachine *pThis,
        PRUnichar * name
    );

    nsresult PR_COM_METHOD (*CanShowConsoleWindow)(
        IMachine *pThis,
        PRBool * canShow
    );

    nsresult PR_COM_METHOD (*ShowConsoleWindow)(
        IMachine *pThis,
        PRUint64 * winId
    );

    nsresult PR_COM_METHOD (*GetGuestProperty)(
        IMachine *pThis,
        PRUnichar * name,
        PRUnichar * * value,
        PRUint64 * timestamp,
        PRUnichar * * flags
    );

    nsresult PR_COM_METHOD (*GetGuestPropertyValue)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * * value
    );

    nsresult PR_COM_METHOD (*GetGuestPropertyTimestamp)(
        IMachine *pThis,
        PRUnichar * property,
        PRUint64 * value
    );

    nsresult PR_COM_METHOD (*SetGuestProperty)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * value,
        PRUnichar * flags
    );

    nsresult PR_COM_METHOD (*SetGuestPropertyValue)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * value
    );

    nsresult PR_COM_METHOD (*EnumerateGuestProperties)(
        IMachine *pThis,
        PRUnichar * patterns,
        PRUint32 *nameSize,
        PRUnichar *** name,
        PRUint32 *valueSize,
        PRUnichar *** value,
        PRUint32 *timestampSize,
        PRUint64* timestamp,
        PRUint32 *flagsSize,
        PRUnichar *** flags
    );

    nsresult PR_COM_METHOD (*QuerySavedThumbnailSize)(
        IMachine *pThis,
        PRUint32 * size,
        PRUint32 * width,
        PRUint32 * height
    );

    nsresult PR_COM_METHOD (*ReadSavedThumbnailToArray)(
        IMachine *pThis,
        PRBool BGR,
        PRUint32 * width,
        PRUint32 * height,
        PRUint32 *dataSize,
        PRUint8** data
    );

    nsresult PR_COM_METHOD (*QuerySavedScreenshotPNGSize)(
        IMachine *pThis,
        PRUint32 * size,
        PRUint32 * width,
        PRUint32 * height
    );

    nsresult PR_COM_METHOD (*ReadSavedScreenshotPNGToArray)(
        IMachine *pThis,
        PRUint32 * width,
        PRUint32 * height,
        PRUint32 *dataSize,
        PRUint8** data
    );

};

struct IMachine
{
    struct IMachine_vtbl *vtbl;
};
/* End of struct IMachine Declaration */


/* Start of struct IConsoleCallback Declaration */
#  define ICONSOLECALLBACK_IID_STR "d6239535-bda2-4ef7-83f4-f4722e4a3b2c"
#  define ICONSOLECALLBACK_IID { \
    0xd6239535, 0xbda2, 0x4ef7, \
    { 0x83, 0xf4, 0xf4, 0x72, 0x2e, 0x4a, 0x3b, 0x2c } \
}
struct IConsoleCallback_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*OnMousePointerShapeChange)(
        IConsoleCallback *pThis,
        PRBool visible,
        PRBool alpha,
        PRUint32 xHot,
        PRUint32 yHot,
        PRUint32 width,
        PRUint32 height,
        PRUint8 * shape
    );

    nsresult PR_COM_METHOD (*OnMouseCapabilityChange)(
        IConsoleCallback *pThis,
        PRBool supportsAbsolute,
        PRBool needsHostCursor
    );

    nsresult PR_COM_METHOD (*OnKeyboardLedsChange)(
        IConsoleCallback *pThis,
        PRBool numLock,
        PRBool capsLock,
        PRBool scrollLock
    );

    nsresult PR_COM_METHOD (*OnStateChange)(
        IConsoleCallback *pThis,
        PRUint32 state
    );

    nsresult PR_COM_METHOD (*OnAdditionsStateChange)(IConsoleCallback *pThis );

    nsresult PR_COM_METHOD (*OnNetworkAdapterChange)(
        IConsoleCallback *pThis,
        INetworkAdapter * networkAdapter
    );

    nsresult PR_COM_METHOD (*OnSerialPortChange)(
        IConsoleCallback *pThis,
        ISerialPort * serialPort
    );

    nsresult PR_COM_METHOD (*OnParallelPortChange)(
        IConsoleCallback *pThis,
        IParallelPort * parallelPort
    );

    nsresult PR_COM_METHOD (*OnStorageControllerChange)(IConsoleCallback *pThis );

    nsresult PR_COM_METHOD (*OnMediumChange)(
        IConsoleCallback *pThis,
        IMediumAttachment * mediumAttachment
    );

    nsresult PR_COM_METHOD (*OnVRDPServerChange)(IConsoleCallback *pThis );

    nsresult PR_COM_METHOD (*OnRemoteDisplayInfoChange)(IConsoleCallback *pThis );

    nsresult PR_COM_METHOD (*OnUSBControllerChange)(IConsoleCallback *pThis );

    nsresult PR_COM_METHOD (*OnUSBDeviceStateChange)(
        IConsoleCallback *pThis,
        IUSBDevice * device,
        PRBool attached,
        IVirtualBoxErrorInfo * error
    );

    nsresult PR_COM_METHOD (*OnSharedFolderChange)(
        IConsoleCallback *pThis,
        PRUint32 scope
    );

    nsresult PR_COM_METHOD (*OnRuntimeError)(
        IConsoleCallback *pThis,
        PRBool fatal,
        PRUnichar * id,
        PRUnichar * message
    );

    nsresult PR_COM_METHOD (*OnCanShowWindow)(
        IConsoleCallback *pThis,
        PRBool * canShow
    );

    nsresult PR_COM_METHOD (*OnShowWindow)(
        IConsoleCallback *pThis,
        PRUint64 * winId
    );

};

struct IConsoleCallback
{
    struct IConsoleCallback_vtbl *vtbl;
};
/* End of struct IConsoleCallback Declaration */


/* Start of struct IRemoteDisplayInfo Declaration */
#  define IREMOTEDISPLAYINFO_IID_STR "b3741084-806f-4c3b-8c42-ebad1a81e45a"
#  define IREMOTEDISPLAYINFO_IID { \
    0xb3741084, 0x806f, 0x4c3b, \
    { 0x8c, 0x42, 0xeb, 0xad, 0x1a, 0x81, 0xe4, 0x5a } \
}
struct IRemoteDisplayInfo_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetActive)(IRemoteDisplayInfo *pThis, PRBool *active);

    nsresult PR_COM_METHOD (*GetPort)(IRemoteDisplayInfo *pThis, PRInt32 *port);

    nsresult PR_COM_METHOD (*GetNumberOfClients)(IRemoteDisplayInfo *pThis, PRUint32 *numberOfClients);

    nsresult PR_COM_METHOD (*GetBeginTime)(IRemoteDisplayInfo *pThis, PRInt64 *beginTime);

    nsresult PR_COM_METHOD (*GetEndTime)(IRemoteDisplayInfo *pThis, PRInt64 *endTime);

    nsresult PR_COM_METHOD (*GetBytesSent)(IRemoteDisplayInfo *pThis, PRUint64 *bytesSent);

    nsresult PR_COM_METHOD (*GetBytesSentTotal)(IRemoteDisplayInfo *pThis, PRUint64 *bytesSentTotal);

    nsresult PR_COM_METHOD (*GetBytesReceived)(IRemoteDisplayInfo *pThis, PRUint64 *bytesReceived);

    nsresult PR_COM_METHOD (*GetBytesReceivedTotal)(IRemoteDisplayInfo *pThis, PRUint64 *bytesReceivedTotal);

    nsresult PR_COM_METHOD (*GetUser)(IRemoteDisplayInfo *pThis, PRUnichar * *user);

    nsresult PR_COM_METHOD (*GetDomain)(IRemoteDisplayInfo *pThis, PRUnichar * *domain);

    nsresult PR_COM_METHOD (*GetClientName)(IRemoteDisplayInfo *pThis, PRUnichar * *clientName);

    nsresult PR_COM_METHOD (*GetClientIP)(IRemoteDisplayInfo *pThis, PRUnichar * *clientIP);

    nsresult PR_COM_METHOD (*GetClientVersion)(IRemoteDisplayInfo *pThis, PRUint32 *clientVersion);

    nsresult PR_COM_METHOD (*GetEncryptionStyle)(IRemoteDisplayInfo *pThis, PRUint32 *encryptionStyle);

};

struct IRemoteDisplayInfo
{
    struct IRemoteDisplayInfo_vtbl *vtbl;
};
/* End of struct IRemoteDisplayInfo Declaration */


/* Start of struct IConsole Declaration */
#  define ICONSOLE_IID_STR "6375231a-c17c-464b-92cb-ae9e128d71c3"
#  define ICONSOLE_IID { \
    0x6375231a, 0xc17c, 0x464b, \
    { 0x92, 0xcb, 0xae, 0x9e, 0x12, 0x8d, 0x71, 0xc3 } \
}
struct IConsole_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetMachine)(IConsole *pThis, IMachine * *machine);

    nsresult PR_COM_METHOD (*GetState)(IConsole *pThis, PRUint32 *state);

    nsresult PR_COM_METHOD (*GetGuest)(IConsole *pThis, IGuest * *guest);

    nsresult PR_COM_METHOD (*GetKeyboard)(IConsole *pThis, IKeyboard * *keyboard);

    nsresult PR_COM_METHOD (*GetMouse)(IConsole *pThis, IMouse * *mouse);

    nsresult PR_COM_METHOD (*GetDisplay)(IConsole *pThis, IDisplay * *display);

    nsresult PR_COM_METHOD (*GetDebugger)(IConsole *pThis, IMachineDebugger * *debugger);

    nsresult PR_COM_METHOD (*GetUSBDevices)(IConsole *pThis, PRUint32 *USBDevicesSize, IUSBDevice * **USBDevices);

    nsresult PR_COM_METHOD (*GetRemoteUSBDevices)(IConsole *pThis, PRUint32 *remoteUSBDevicesSize, IHostUSBDevice * **remoteUSBDevices);

    nsresult PR_COM_METHOD (*GetSharedFolders)(IConsole *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult PR_COM_METHOD (*GetRemoteDisplayInfo)(IConsole *pThis, IRemoteDisplayInfo * *remoteDisplayInfo);

    nsresult PR_COM_METHOD (*PowerUp)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*PowerUpPaused)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*PowerDown)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*Reset)(IConsole *pThis );

    nsresult PR_COM_METHOD (*Pause)(IConsole *pThis );

    nsresult PR_COM_METHOD (*Resume)(IConsole *pThis );

    nsresult PR_COM_METHOD (*PowerButton)(IConsole *pThis );

    nsresult PR_COM_METHOD (*SleepButton)(IConsole *pThis );

    nsresult PR_COM_METHOD (*GetPowerButtonHandled)(
        IConsole *pThis,
        PRBool * handled
    );

    nsresult PR_COM_METHOD (*GetGuestEnteredACPIMode)(
        IConsole *pThis,
        PRBool * entered
    );

    nsresult PR_COM_METHOD (*SaveState)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*AdoptSavedState)(
        IConsole *pThis,
        PRUnichar * savedStateFile
    );

    nsresult PR_COM_METHOD (*ForgetSavedState)(
        IConsole *pThis,
        PRBool remove
    );

    nsresult PR_COM_METHOD (*GetDeviceActivity)(
        IConsole *pThis,
        PRUint32 type,
        PRUint32 * activity
    );

    nsresult PR_COM_METHOD (*AttachUSBDevice)(
        IConsole *pThis,
        PRUnichar * id
    );

    nsresult PR_COM_METHOD (*DetachUSBDevice)(
        IConsole *pThis,
        PRUnichar * id,
        IUSBDevice * * device
    );

    nsresult PR_COM_METHOD (*FindUSBDeviceByAddress)(
        IConsole *pThis,
        PRUnichar * name,
        IUSBDevice * * device
    );

    nsresult PR_COM_METHOD (*FindUSBDeviceById)(
        IConsole *pThis,
        PRUnichar * id,
        IUSBDevice * * device
    );

    nsresult PR_COM_METHOD (*CreateSharedFolder)(
        IConsole *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable
    );

    nsresult PR_COM_METHOD (*RemoveSharedFolder)(
        IConsole *pThis,
        PRUnichar * name
    );

    nsresult PR_COM_METHOD (*TakeSnapshot)(
        IConsole *pThis,
        PRUnichar * name,
        PRUnichar * description,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*DeleteSnapshot)(
        IConsole *pThis,
        PRUnichar * id,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*RestoreSnapshot)(
        IConsole *pThis,
        ISnapshot * snapshot,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*Teleport)(
        IConsole *pThis,
        PRUnichar * hostname,
        PRUint32 tcpport,
        PRUnichar * password,
        PRUint32 maxDowntime,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*RegisterCallback)(
        IConsole *pThis,
        IConsoleCallback * callback
    );

    nsresult PR_COM_METHOD (*UnregisterCallback)(
        IConsole *pThis,
        IConsoleCallback * callback
    );

};

struct IConsole
{
    struct IConsole_vtbl *vtbl;
};
/* End of struct IConsole Declaration */


/* Start of struct IHostNetworkInterface Declaration */
#  define IHOSTNETWORKINTERFACE_IID_STR "ce6fae58-7642-4102-b5db-c9005c2320a8"
#  define IHOSTNETWORKINTERFACE_IID { \
    0xce6fae58, 0x7642, 0x4102, \
    { 0xb5, 0xdb, 0xc9, 0x00, 0x5c, 0x23, 0x20, 0xa8 } \
}
struct IHostNetworkInterface_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetName)(IHostNetworkInterface *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetId)(IHostNetworkInterface *pThis, PRUnichar * *id);

    nsresult PR_COM_METHOD (*GetNetworkName)(IHostNetworkInterface *pThis, PRUnichar * *networkName);

    nsresult PR_COM_METHOD (*GetDhcpEnabled)(IHostNetworkInterface *pThis, PRBool *dhcpEnabled);

    nsresult PR_COM_METHOD (*GetIPAddress)(IHostNetworkInterface *pThis, PRUnichar * *IPAddress);

    nsresult PR_COM_METHOD (*GetNetworkMask)(IHostNetworkInterface *pThis, PRUnichar * *networkMask);

    nsresult PR_COM_METHOD (*GetIPV6Supported)(IHostNetworkInterface *pThis, PRBool *IPV6Supported);

    nsresult PR_COM_METHOD (*GetIPV6Address)(IHostNetworkInterface *pThis, PRUnichar * *IPV6Address);

    nsresult PR_COM_METHOD (*GetIPV6NetworkMaskPrefixLength)(IHostNetworkInterface *pThis, PRUint32 *IPV6NetworkMaskPrefixLength);

    nsresult PR_COM_METHOD (*GetHardwareAddress)(IHostNetworkInterface *pThis, PRUnichar * *hardwareAddress);

    nsresult PR_COM_METHOD (*GetMediumType)(IHostNetworkInterface *pThis, PRUint32 *mediumType);

    nsresult PR_COM_METHOD (*GetStatus)(IHostNetworkInterface *pThis, PRUint32 *status);

    nsresult PR_COM_METHOD (*GetInterfaceType)(IHostNetworkInterface *pThis, PRUint32 *interfaceType);

    nsresult PR_COM_METHOD (*EnableStaticIpConfig)(
        IHostNetworkInterface *pThis,
        PRUnichar * IPAddress,
        PRUnichar * networkMask
    );

    nsresult PR_COM_METHOD (*EnableStaticIpConfigV6)(
        IHostNetworkInterface *pThis,
        PRUnichar * IPV6Address,
        PRUint32 IPV6NetworkMaskPrefixLength
    );

    nsresult PR_COM_METHOD (*EnableDynamicIpConfig)(IHostNetworkInterface *pThis );

    nsresult PR_COM_METHOD (*DhcpRediscover)(IHostNetworkInterface *pThis );

};

struct IHostNetworkInterface
{
    struct IHostNetworkInterface_vtbl *vtbl;
};
/* End of struct IHostNetworkInterface Declaration */


/* Start of struct IHost Declaration */
#  define IHOST_IID_STR "e380cbfc-ae65-4fa6-899e-45ded6b3132a"
#  define IHOST_IID { \
    0xe380cbfc, 0xae65, 0x4fa6, \
    { 0x89, 0x9e, 0x45, 0xde, 0xd6, 0xb3, 0x13, 0x2a } \
}
struct IHost_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetDVDDrives)(IHost *pThis, PRUint32 *DVDDrivesSize, IMedium * **DVDDrives);

    nsresult PR_COM_METHOD (*GetFloppyDrives)(IHost *pThis, PRUint32 *floppyDrivesSize, IMedium * **floppyDrives);

    nsresult PR_COM_METHOD (*GetUSBDevices)(IHost *pThis, PRUint32 *USBDevicesSize, IHostUSBDevice * **USBDevices);

    nsresult PR_COM_METHOD (*GetUSBDeviceFilters)(IHost *pThis, PRUint32 *USBDeviceFiltersSize, IHostUSBDeviceFilter * **USBDeviceFilters);

    nsresult PR_COM_METHOD (*GetNetworkInterfaces)(IHost *pThis, PRUint32 *networkInterfacesSize, IHostNetworkInterface * **networkInterfaces);

    nsresult PR_COM_METHOD (*GetProcessorCount)(IHost *pThis, PRUint32 *processorCount);

    nsresult PR_COM_METHOD (*GetProcessorOnlineCount)(IHost *pThis, PRUint32 *processorOnlineCount);

    nsresult PR_COM_METHOD (*GetMemorySize)(IHost *pThis, PRUint32 *memorySize);

    nsresult PR_COM_METHOD (*GetMemoryAvailable)(IHost *pThis, PRUint32 *memoryAvailable);

    nsresult PR_COM_METHOD (*GetOperatingSystem)(IHost *pThis, PRUnichar * *operatingSystem);

    nsresult PR_COM_METHOD (*GetOSVersion)(IHost *pThis, PRUnichar * *OSVersion);

    nsresult PR_COM_METHOD (*GetUTCTime)(IHost *pThis, PRInt64 *UTCTime);

    nsresult PR_COM_METHOD (*GetAcceleration3DAvailable)(IHost *pThis, PRBool *Acceleration3DAvailable);

    nsresult PR_COM_METHOD (*GetProcessorSpeed)(
        IHost *pThis,
        PRUint32 cpuId,
        PRUint32 * speed
    );

    nsresult PR_COM_METHOD (*GetProcessorFeature)(
        IHost *pThis,
        PRUint32 feature,
        PRBool * supported
    );

    nsresult PR_COM_METHOD (*GetProcessorDescription)(
        IHost *pThis,
        PRUint32 cpuId,
        PRUnichar * * description
    );

    nsresult PR_COM_METHOD (*GetProcessorCpuIdLeaf)(
        IHost *pThis,
        PRUint32 cpuId,
        PRUint32 leaf,
        PRUint32 subLeaf,
        PRUint32 * valEax,
        PRUint32 * valEbx,
        PRUint32 * valEcx,
        PRUint32 * valEdx
    );

    nsresult PR_COM_METHOD (*CreateHostOnlyNetworkInterface)(
        IHost *pThis,
        IHostNetworkInterface * * hostInterface,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*RemoveHostOnlyNetworkInterface)(
        IHost *pThis,
        PRUnichar * id,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*CreateUSBDeviceFilter)(
        IHost *pThis,
        PRUnichar * name,
        IHostUSBDeviceFilter * * filter
    );

    nsresult PR_COM_METHOD (*InsertUSBDeviceFilter)(
        IHost *pThis,
        PRUint32 position,
        IHostUSBDeviceFilter * filter
    );

    nsresult PR_COM_METHOD (*RemoveUSBDeviceFilter)(
        IHost *pThis,
        PRUint32 position
    );

    nsresult PR_COM_METHOD (*FindHostDVDDrive)(
        IHost *pThis,
        PRUnichar * name,
        IMedium * * drive
    );

    nsresult PR_COM_METHOD (*FindHostFloppyDrive)(
        IHost *pThis,
        PRUnichar * name,
        IMedium * * drive
    );

    nsresult PR_COM_METHOD (*FindHostNetworkInterfaceByName)(
        IHost *pThis,
        PRUnichar * name,
        IHostNetworkInterface * * networkInterface
    );

    nsresult PR_COM_METHOD (*FindHostNetworkInterfaceById)(
        IHost *pThis,
        PRUnichar * id,
        IHostNetworkInterface * * networkInterface
    );

    nsresult PR_COM_METHOD (*FindHostNetworkInterfacesOfType)(
        IHost *pThis,
        PRUint32 type,
        PRUint32 *networkInterfacesSize,
        IHostNetworkInterface *** networkInterfaces
    );

    nsresult PR_COM_METHOD (*FindUSBDeviceById)(
        IHost *pThis,
        PRUnichar * id,
        IHostUSBDevice * * device
    );

    nsresult PR_COM_METHOD (*FindUSBDeviceByAddress)(
        IHost *pThis,
        PRUnichar * name,
        IHostUSBDevice * * device
    );

};

struct IHost
{
    struct IHost_vtbl *vtbl;
};
/* End of struct IHost Declaration */


/* Start of struct ISystemProperties Declaration */
#  define ISYSTEMPROPERTIES_IID_STR "8030645c-8fef-4320-bb7b-c829f00069dc"
#  define ISYSTEMPROPERTIES_IID { \
    0x8030645c, 0x8fef, 0x4320, \
    { 0xbb, 0x7b, 0xc8, 0x29, 0xf0, 0x00, 0x69, 0xdc } \
}
struct ISystemProperties_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetMinGuestRAM)(ISystemProperties *pThis, PRUint32 *minGuestRAM);

    nsresult PR_COM_METHOD (*GetMaxGuestRAM)(ISystemProperties *pThis, PRUint32 *maxGuestRAM);

    nsresult PR_COM_METHOD (*GetMinGuestVRAM)(ISystemProperties *pThis, PRUint32 *minGuestVRAM);

    nsresult PR_COM_METHOD (*GetMaxGuestVRAM)(ISystemProperties *pThis, PRUint32 *maxGuestVRAM);

    nsresult PR_COM_METHOD (*GetMinGuestCPUCount)(ISystemProperties *pThis, PRUint32 *minGuestCPUCount);

    nsresult PR_COM_METHOD (*GetMaxGuestCPUCount)(ISystemProperties *pThis, PRUint32 *maxGuestCPUCount);

    nsresult PR_COM_METHOD (*GetMaxVDISize)(ISystemProperties *pThis, PRUint64 *maxVDISize);

    nsresult PR_COM_METHOD (*GetNetworkAdapterCount)(ISystemProperties *pThis, PRUint32 *networkAdapterCount);

    nsresult PR_COM_METHOD (*GetSerialPortCount)(ISystemProperties *pThis, PRUint32 *serialPortCount);

    nsresult PR_COM_METHOD (*GetParallelPortCount)(ISystemProperties *pThis, PRUint32 *parallelPortCount);

    nsresult PR_COM_METHOD (*GetMaxBootPosition)(ISystemProperties *pThis, PRUint32 *maxBootPosition);

    nsresult PR_COM_METHOD (*GetDefaultMachineFolder)(ISystemProperties *pThis, PRUnichar * *defaultMachineFolder);
    nsresult PR_COM_METHOD (*SetDefaultMachineFolder)(ISystemProperties *pThis, PRUnichar * defaultMachineFolder);

    nsresult PR_COM_METHOD (*GetDefaultHardDiskFolder)(ISystemProperties *pThis, PRUnichar * *defaultHardDiskFolder);
    nsresult PR_COM_METHOD (*SetDefaultHardDiskFolder)(ISystemProperties *pThis, PRUnichar * defaultHardDiskFolder);

    nsresult PR_COM_METHOD (*GetMediumFormats)(ISystemProperties *pThis, PRUint32 *mediumFormatsSize, IMediumFormat * **mediumFormats);

    nsresult PR_COM_METHOD (*GetDefaultHardDiskFormat)(ISystemProperties *pThis, PRUnichar * *defaultHardDiskFormat);
    nsresult PR_COM_METHOD (*SetDefaultHardDiskFormat)(ISystemProperties *pThis, PRUnichar * defaultHardDiskFormat);

    nsresult PR_COM_METHOD (*GetRemoteDisplayAuthLibrary)(ISystemProperties *pThis, PRUnichar * *remoteDisplayAuthLibrary);
    nsresult PR_COM_METHOD (*SetRemoteDisplayAuthLibrary)(ISystemProperties *pThis, PRUnichar * remoteDisplayAuthLibrary);

    nsresult PR_COM_METHOD (*GetWebServiceAuthLibrary)(ISystemProperties *pThis, PRUnichar * *webServiceAuthLibrary);
    nsresult PR_COM_METHOD (*SetWebServiceAuthLibrary)(ISystemProperties *pThis, PRUnichar * webServiceAuthLibrary);

    nsresult PR_COM_METHOD (*GetLogHistoryCount)(ISystemProperties *pThis, PRUint32 *LogHistoryCount);
    nsresult PR_COM_METHOD (*SetLogHistoryCount)(ISystemProperties *pThis, PRUint32 LogHistoryCount);

    nsresult PR_COM_METHOD (*GetDefaultAudioDriver)(ISystemProperties *pThis, PRUint32 *defaultAudioDriver);

    nsresult PR_COM_METHOD (*GetMaxDevicesPerPortForStorageBus)(
        ISystemProperties *pThis,
        PRUint32 bus,
        PRUint32 * maxDevicesPerPort
    );

    nsresult PR_COM_METHOD (*GetMinPortCountForStorageBus)(
        ISystemProperties *pThis,
        PRUint32 bus,
        PRUint32 * minPortCount
    );

    nsresult PR_COM_METHOD (*GetMaxPortCountForStorageBus)(
        ISystemProperties *pThis,
        PRUint32 bus,
        PRUint32 * maxPortCount
    );

    nsresult PR_COM_METHOD (*GetMaxInstancesOfStorageBus)(
        ISystemProperties *pThis,
        PRUint32 bus,
        PRUint32 * maxInstances
    );

    nsresult PR_COM_METHOD (*GetDeviceTypesForStorageBus)(
        ISystemProperties *pThis,
        PRUint32 bus,
        PRUint32 *deviceTypesSize,
        PRUint32** deviceTypes
    );

};

struct ISystemProperties
{
    struct ISystemProperties_vtbl *vtbl;
};
/* End of struct ISystemProperties Declaration */


/* Start of struct IGuestOSType Declaration */
#  define IGUESTOSTYPE_IID_STR "cfe9e64c-4430-435b-9e7c-e3d8e417bd58"
#  define IGUESTOSTYPE_IID { \
    0xcfe9e64c, 0x4430, 0x435b, \
    { 0x9e, 0x7c, 0xe3, 0xd8, 0xe4, 0x17, 0xbd, 0x58 } \
}
struct IGuestOSType_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetFamilyId)(IGuestOSType *pThis, PRUnichar * *familyId);

    nsresult PR_COM_METHOD (*GetFamilyDescription)(IGuestOSType *pThis, PRUnichar * *familyDescription);

    nsresult PR_COM_METHOD (*GetId)(IGuestOSType *pThis, PRUnichar * *id);

    nsresult PR_COM_METHOD (*GetDescription)(IGuestOSType *pThis, PRUnichar * *description);

    nsresult PR_COM_METHOD (*GetIs64Bit)(IGuestOSType *pThis, PRBool *is64Bit);

    nsresult PR_COM_METHOD (*GetRecommendedIOAPIC)(IGuestOSType *pThis, PRBool *recommendedIOAPIC);

    nsresult PR_COM_METHOD (*GetRecommendedVirtEx)(IGuestOSType *pThis, PRBool *recommendedVirtEx);

    nsresult PR_COM_METHOD (*GetRecommendedRAM)(IGuestOSType *pThis, PRUint32 *recommendedRAM);

    nsresult PR_COM_METHOD (*GetRecommendedVRAM)(IGuestOSType *pThis, PRUint32 *recommendedVRAM);

    nsresult PR_COM_METHOD (*GetRecommendedHDD)(IGuestOSType *pThis, PRUint32 *recommendedHDD);

    nsresult PR_COM_METHOD (*GetAdapterType)(IGuestOSType *pThis, PRUint32 *adapterType);

};

struct IGuestOSType
{
    struct IGuestOSType_vtbl *vtbl;
};
/* End of struct IGuestOSType Declaration */


/* Start of struct IGuest Declaration */
#  define IGUEST_IID_STR "d8556fca-81bc-12af-fca3-365528fa38ca"
#  define IGUEST_IID { \
    0xd8556fca, 0x81bc, 0x12af, \
    { 0xfc, 0xa3, 0x36, 0x55, 0x28, 0xfa, 0x38, 0xca } \
}
struct IGuest_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetOSTypeId)(IGuest *pThis, PRUnichar * *OSTypeId);

    nsresult PR_COM_METHOD (*GetAdditionsActive)(IGuest *pThis, PRBool *additionsActive);

    nsresult PR_COM_METHOD (*GetAdditionsVersion)(IGuest *pThis, PRUnichar * *additionsVersion);

    nsresult PR_COM_METHOD (*GetSupportsSeamless)(IGuest *pThis, PRBool *supportsSeamless);

    nsresult PR_COM_METHOD (*GetSupportsGraphics)(IGuest *pThis, PRBool *supportsGraphics);

    nsresult PR_COM_METHOD (*GetMemoryBalloonSize)(IGuest *pThis, PRUint32 *memoryBalloonSize);
    nsresult PR_COM_METHOD (*SetMemoryBalloonSize)(IGuest *pThis, PRUint32 memoryBalloonSize);

    nsresult PR_COM_METHOD (*GetStatisticsUpdateInterval)(IGuest *pThis, PRUint32 *statisticsUpdateInterval);
    nsresult PR_COM_METHOD (*SetStatisticsUpdateInterval)(IGuest *pThis, PRUint32 statisticsUpdateInterval);

    nsresult PR_COM_METHOD (*SetCredentials)(
        IGuest *pThis,
        PRUnichar * userName,
        PRUnichar * password,
        PRUnichar * domain,
        PRBool allowInteractiveLogon
    );

    nsresult PR_COM_METHOD (*GetStatistic)(
        IGuest *pThis,
        PRUint32 cpuId,
        PRUint32 statistic,
        PRUint32 * statVal
    );

};

struct IGuest
{
    struct IGuest_vtbl *vtbl;
};
/* End of struct IGuest Declaration */


/* Start of struct IProgress Declaration */
#  define IPROGRESS_IID_STR "856aa038-853f-42e2-acf7-6e7b02dbe294"
#  define IPROGRESS_IID { \
    0x856aa038, 0x853f, 0x42e2, \
    { 0xac, 0xf7, 0x6e, 0x7b, 0x02, 0xdb, 0xe2, 0x94 } \
}
struct IProgress_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetId)(IProgress *pThis, PRUnichar * *id);

    nsresult PR_COM_METHOD (*GetDescription)(IProgress *pThis, PRUnichar * *description);

    nsresult PR_COM_METHOD (*GetInitiator)(IProgress *pThis, nsISupports * *initiator);

    nsresult PR_COM_METHOD (*GetCancelable)(IProgress *pThis, PRBool *cancelable);

    nsresult PR_COM_METHOD (*GetPercent)(IProgress *pThis, PRUint32 *percent);

    nsresult PR_COM_METHOD (*GetTimeRemaining)(IProgress *pThis, PRInt32 *timeRemaining);

    nsresult PR_COM_METHOD (*GetCompleted)(IProgress *pThis, PRBool *completed);

    nsresult PR_COM_METHOD (*GetCanceled)(IProgress *pThis, PRBool *canceled);

    nsresult PR_COM_METHOD (*GetResultCode)(IProgress *pThis, PRInt32 *resultCode);

    nsresult PR_COM_METHOD (*GetErrorInfo)(IProgress *pThis, IVirtualBoxErrorInfo * *errorInfo);

    nsresult PR_COM_METHOD (*GetOperationCount)(IProgress *pThis, PRUint32 *operationCount);

    nsresult PR_COM_METHOD (*GetOperation)(IProgress *pThis, PRUint32 *operation);

    nsresult PR_COM_METHOD (*GetOperationDescription)(IProgress *pThis, PRUnichar * *operationDescription);

    nsresult PR_COM_METHOD (*GetOperationPercent)(IProgress *pThis, PRUint32 *operationPercent);

    nsresult PR_COM_METHOD (*GetTimeout)(IProgress *pThis, PRUint32 *timeout);
    nsresult PR_COM_METHOD (*SetTimeout)(IProgress *pThis, PRUint32 timeout);

    nsresult PR_COM_METHOD (*SetCurrentOperationProgress)(
        IProgress *pThis,
        PRUint32 percent
    );

    nsresult PR_COM_METHOD (*SetNextOperation)(
        IProgress *pThis,
        PRUnichar * nextOperationDescription,
        PRUint32 nextOperationsWeight
    );

    nsresult PR_COM_METHOD (*WaitForCompletion)(
        IProgress *pThis,
        PRInt32 timeout
    );

    nsresult PR_COM_METHOD (*WaitForOperationCompletion)(
        IProgress *pThis,
        PRUint32 operation,
        PRInt32 timeout
    );

    nsresult PR_COM_METHOD (*Cancel)(IProgress *pThis );

};

struct IProgress
{
    struct IProgress_vtbl *vtbl;
};
/* End of struct IProgress Declaration */


/* Start of struct ISnapshot Declaration */
#  define ISNAPSHOT_IID_STR "1a2d0551-58a4-4107-857e-ef414fc42ffc"
#  define ISNAPSHOT_IID { \
    0x1a2d0551, 0x58a4, 0x4107, \
    { 0x85, 0x7e, 0xef, 0x41, 0x4f, 0xc4, 0x2f, 0xfc } \
}
struct ISnapshot_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetId)(ISnapshot *pThis, PRUnichar * *id);

    nsresult PR_COM_METHOD (*GetName)(ISnapshot *pThis, PRUnichar * *name);
    nsresult PR_COM_METHOD (*SetName)(ISnapshot *pThis, PRUnichar * name);

    nsresult PR_COM_METHOD (*GetDescription)(ISnapshot *pThis, PRUnichar * *description);
    nsresult PR_COM_METHOD (*SetDescription)(ISnapshot *pThis, PRUnichar * description);

    nsresult PR_COM_METHOD (*GetTimeStamp)(ISnapshot *pThis, PRInt64 *timeStamp);

    nsresult PR_COM_METHOD (*GetOnline)(ISnapshot *pThis, PRBool *online);

    nsresult PR_COM_METHOD (*GetMachine)(ISnapshot *pThis, IMachine * *machine);

    nsresult PR_COM_METHOD (*GetParent)(ISnapshot *pThis, ISnapshot * *parent);

    nsresult PR_COM_METHOD (*GetChildren)(ISnapshot *pThis, PRUint32 *childrenSize, ISnapshot * **children);

};

struct ISnapshot
{
    struct ISnapshot_vtbl *vtbl;
};
/* End of struct ISnapshot Declaration */


/* Start of struct IMediumAttachment Declaration */
#  define IMEDIUMATTACHMENT_IID_STR "e58eb3eb-8627-428b-bdf8-34487c848de5"
#  define IMEDIUMATTACHMENT_IID { \
    0xe58eb3eb, 0x8627, 0x428b, \
    { 0xbd, 0xf8, 0x34, 0x48, 0x7c, 0x84, 0x8d, 0xe5 } \
}
struct IMediumAttachment_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetMedium)(IMediumAttachment *pThis, IMedium * *medium);

    nsresult PR_COM_METHOD (*GetController)(IMediumAttachment *pThis, PRUnichar * *controller);

    nsresult PR_COM_METHOD (*GetPort)(IMediumAttachment *pThis, PRInt32 *port);

    nsresult PR_COM_METHOD (*GetDevice)(IMediumAttachment *pThis, PRInt32 *device);

    nsresult PR_COM_METHOD (*GetType)(IMediumAttachment *pThis, PRUint32 *type);

    nsresult PR_COM_METHOD (*GetPassthrough)(IMediumAttachment *pThis, PRBool *passthrough);

};

struct IMediumAttachment
{
    struct IMediumAttachment_vtbl *vtbl;
};
/* End of struct IMediumAttachment Declaration */


/* Start of struct IMedium Declaration */
#  define IMEDIUM_IID_STR "aa8167ba-df72-4738-b740-9b84377ba9f1"
#  define IMEDIUM_IID { \
    0xaa8167ba, 0xdf72, 0x4738, \
    { 0xb7, 0x40, 0x9b, 0x84, 0x37, 0x7b, 0xa9, 0xf1 } \
}
struct IMedium_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetId)(IMedium *pThis, PRUnichar * *id);

    nsresult PR_COM_METHOD (*GetDescription)(IMedium *pThis, PRUnichar * *description);
    nsresult PR_COM_METHOD (*SetDescription)(IMedium *pThis, PRUnichar * description);

    nsresult PR_COM_METHOD (*GetState)(IMedium *pThis, PRUint32 *state);

    nsresult PR_COM_METHOD (*GetLocation)(IMedium *pThis, PRUnichar * *location);
    nsresult PR_COM_METHOD (*SetLocation)(IMedium *pThis, PRUnichar * location);

    nsresult PR_COM_METHOD (*GetName)(IMedium *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetDeviceType)(IMedium *pThis, PRUint32 *deviceType);

    nsresult PR_COM_METHOD (*GetHostDrive)(IMedium *pThis, PRBool *hostDrive);

    nsresult PR_COM_METHOD (*GetSize)(IMedium *pThis, PRUint64 *size);

    nsresult PR_COM_METHOD (*GetFormat)(IMedium *pThis, PRUnichar * *format);

    nsresult PR_COM_METHOD (*GetType)(IMedium *pThis, PRUint32 *type);
    nsresult PR_COM_METHOD (*SetType)(IMedium *pThis, PRUint32 type);

    nsresult PR_COM_METHOD (*GetParent)(IMedium *pThis, IMedium * *parent);

    nsresult PR_COM_METHOD (*GetChildren)(IMedium *pThis, PRUint32 *childrenSize, IMedium * **children);

    nsresult PR_COM_METHOD (*GetBase)(IMedium *pThis, IMedium * *base);

    nsresult PR_COM_METHOD (*GetReadOnly)(IMedium *pThis, PRBool *readOnly);

    nsresult PR_COM_METHOD (*GetLogicalSize)(IMedium *pThis, PRUint64 *logicalSize);

    nsresult PR_COM_METHOD (*GetAutoReset)(IMedium *pThis, PRBool *autoReset);
    nsresult PR_COM_METHOD (*SetAutoReset)(IMedium *pThis, PRBool autoReset);

    nsresult PR_COM_METHOD (*GetLastAccessError)(IMedium *pThis, PRUnichar * *lastAccessError);

    nsresult PR_COM_METHOD (*GetMachineIds)(IMedium *pThis, PRUint32 *machineIdsSize, PRUnichar * **machineIds);

    nsresult PR_COM_METHOD (*RefreshState)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult PR_COM_METHOD (*GetSnapshotIds)(
        IMedium *pThis,
        PRUnichar * machineId,
        PRUint32 *snapshotIdsSize,
        PRUnichar *** snapshotIds
    );

    nsresult PR_COM_METHOD (*LockRead)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult PR_COM_METHOD (*UnlockRead)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult PR_COM_METHOD (*LockWrite)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult PR_COM_METHOD (*UnlockWrite)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult PR_COM_METHOD (*Close)(IMedium *pThis );

    nsresult PR_COM_METHOD (*GetProperty)(
        IMedium *pThis,
        PRUnichar * name,
        PRUnichar * * value
    );

    nsresult PR_COM_METHOD (*SetProperty)(
        IMedium *pThis,
        PRUnichar * name,
        PRUnichar * value
    );

    nsresult PR_COM_METHOD (*GetProperties)(
        IMedium *pThis,
        PRUnichar * names,
        PRUint32 *returnNamesSize,
        PRUnichar *** returnNames,
        PRUint32 *returnValuesSize,
        PRUnichar *** returnValues
    );

    nsresult PR_COM_METHOD (*SetProperties)(
        IMedium *pThis,
        PRUint32 namesSize,
        PRUnichar ** names,
        PRUint32 valuesSize,
        PRUnichar ** values
    );

    nsresult PR_COM_METHOD (*CreateBaseStorage)(
        IMedium *pThis,
        PRUint64 logicalSize,
        PRUint32 variant,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*DeleteStorage)(
        IMedium *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*CreateDiffStorage)(
        IMedium *pThis,
        IMedium * target,
        PRUint32 variant,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*MergeTo)(
        IMedium *pThis,
        PRUnichar * targetId,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*CloneTo)(
        IMedium *pThis,
        IMedium * target,
        PRUint32 variant,
        IMedium * parent,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*Compact)(
        IMedium *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*Resize)(
        IMedium *pThis,
        PRUint64 logicalSize,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*Reset)(
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
#  define IMEDIUMFORMAT_IID_STR "89f52554-d469-4799-9fad-1705e86a08b1"
#  define IMEDIUMFORMAT_IID { \
    0x89f52554, 0xd469, 0x4799, \
    { 0x9f, 0xad, 0x17, 0x05, 0xe8, 0x6a, 0x08, 0xb1 } \
}
struct IMediumFormat_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetId)(IMediumFormat *pThis, PRUnichar * *id);

    nsresult PR_COM_METHOD (*GetName)(IMediumFormat *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetFileExtensions)(IMediumFormat *pThis, PRUint32 *fileExtensionsSize, PRUnichar * **fileExtensions);

    nsresult PR_COM_METHOD (*GetCapabilities)(IMediumFormat *pThis, PRUint32 *capabilities);

    nsresult PR_COM_METHOD (*DescribeProperties)(
        IMediumFormat *pThis,
        PRUint32 *namesSize,
        PRUnichar *** names,
        PRUint32 *descriptionSize,
        PRUnichar *** description,
        PRUint32 *typesSize,
        PRUint32* types,
        PRUint32 *flagsSize,
        PRUint32* flags,
        PRUint32 *defaultsSize,
        PRUnichar *** defaults
    );

};

struct IMediumFormat
{
    struct IMediumFormat_vtbl *vtbl;
};
/* End of struct IMediumFormat Declaration */


/* Start of struct IKeyboard Declaration */
#  define IKEYBOARD_IID_STR "2d1a531b-4c6e-49cc-8af6-5c857b78b5d7"
#  define IKEYBOARD_IID { \
    0x2d1a531b, 0x4c6e, 0x49cc, \
    { 0x8a, 0xf6, 0x5c, 0x85, 0x7b, 0x78, 0xb5, 0xd7 } \
}
struct IKeyboard_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*PutScancode)(
        IKeyboard *pThis,
        PRInt32 scancode
    );

    nsresult PR_COM_METHOD (*PutScancodes)(
        IKeyboard *pThis,
        PRUint32 scancodesSize,
        PRInt32* scancodes,
        PRUint32 * codesStored
    );

    nsresult PR_COM_METHOD (*PutCAD)(IKeyboard *pThis );

};

struct IKeyboard
{
    struct IKeyboard_vtbl *vtbl;
};
/* End of struct IKeyboard Declaration */


/* Start of struct IMouse Declaration */
#  define IMOUSE_IID_STR "7c0f2eae-f92d-498c-b802-e1a3763774dc"
#  define IMOUSE_IID { \
    0x7c0f2eae, 0xf92d, 0x498c, \
    { 0xb8, 0x02, 0xe1, 0xa3, 0x76, 0x37, 0x74, 0xdc } \
}
struct IMouse_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetAbsoluteSupported)(IMouse *pThis, PRBool *absoluteSupported);

    nsresult PR_COM_METHOD (*PutMouseEvent)(
        IMouse *pThis,
        PRInt32 dx,
        PRInt32 dy,
        PRInt32 dz,
        PRInt32 dw,
        PRInt32 buttonState
    );

    nsresult PR_COM_METHOD (*PutMouseEventAbsolute)(
        IMouse *pThis,
        PRInt32 x,
        PRInt32 y,
        PRInt32 dz,
        PRInt32 dw,
        PRInt32 buttonState
    );

};

struct IMouse
{
    struct IMouse_vtbl *vtbl;
};
/* End of struct IMouse Declaration */


/* Start of struct IFramebuffer Declaration */
#  define IFRAMEBUFFER_IID_STR "b7ed347a-5765-40a0-ae1c-f543eb4ddeaf"
#  define IFRAMEBUFFER_IID { \
    0xb7ed347a, 0x5765, 0x40a0, \
    { 0xae, 0x1c, 0xf5, 0x43, 0xeb, 0x4d, 0xde, 0xaf } \
}
struct IFramebuffer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetAddress)(IFramebuffer *pThis, PRUint8 * *address);

    nsresult PR_COM_METHOD (*GetWidth)(IFramebuffer *pThis, PRUint32 *width);

    nsresult PR_COM_METHOD (*GetHeight)(IFramebuffer *pThis, PRUint32 *height);

    nsresult PR_COM_METHOD (*GetBitsPerPixel)(IFramebuffer *pThis, PRUint32 *bitsPerPixel);

    nsresult PR_COM_METHOD (*GetBytesPerLine)(IFramebuffer *pThis, PRUint32 *bytesPerLine);

    nsresult PR_COM_METHOD (*GetPixelFormat)(IFramebuffer *pThis, PRUint32 *pixelFormat);

    nsresult PR_COM_METHOD (*GetUsesGuestVRAM)(IFramebuffer *pThis, PRBool *usesGuestVRAM);

    nsresult PR_COM_METHOD (*GetHeightReduction)(IFramebuffer *pThis, PRUint32 *heightReduction);

    nsresult PR_COM_METHOD (*GetOverlay)(IFramebuffer *pThis, IFramebufferOverlay * *overlay);

    nsresult PR_COM_METHOD (*GetWinId)(IFramebuffer *pThis, PRUint64 *winId);

    nsresult PR_COM_METHOD (*Lock)(IFramebuffer *pThis );

    nsresult PR_COM_METHOD (*Unlock)(IFramebuffer *pThis );

    nsresult PR_COM_METHOD (*NotifyUpdate)(
        IFramebuffer *pThis,
        PRUint32 x,
        PRUint32 y,
        PRUint32 width,
        PRUint32 height
    );

    nsresult PR_COM_METHOD (*RequestResize)(
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

    nsresult PR_COM_METHOD (*VideoModeSupported)(
        IFramebuffer *pThis,
        PRUint32 width,
        PRUint32 height,
        PRUint32 bpp,
        PRBool * supported
    );

    nsresult PR_COM_METHOD (*GetVisibleRegion)(
        IFramebuffer *pThis,
        PRUint8 * rectangles,
        PRUint32 count,
        PRUint32 * countCopied
    );

    nsresult PR_COM_METHOD (*SetVisibleRegion)(
        IFramebuffer *pThis,
        PRUint8 * rectangles,
        PRUint32 count
    );

    nsresult PR_COM_METHOD (*ProcessVHWACommand)(
        IFramebuffer *pThis,
        PRUint8 * command
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

    nsresult PR_COM_METHOD (*GetX)(IFramebufferOverlay *pThis, PRUint32 *x);

    nsresult PR_COM_METHOD (*GetY)(IFramebufferOverlay *pThis, PRUint32 *y);

    nsresult PR_COM_METHOD (*GetVisible)(IFramebufferOverlay *pThis, PRBool *visible);
    nsresult PR_COM_METHOD (*SetVisible)(IFramebufferOverlay *pThis, PRBool visible);

    nsresult PR_COM_METHOD (*GetAlpha)(IFramebufferOverlay *pThis, PRUint32 *alpha);
    nsresult PR_COM_METHOD (*SetAlpha)(IFramebufferOverlay *pThis, PRUint32 alpha);

    nsresult PR_COM_METHOD (*Move)(
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
#  define IDISPLAY_IID_STR "e2a38ebc-d854-4a3e-bc2e-fdf5ac4a0000"
#  define IDISPLAY_IID { \
    0xe2a38ebc, 0xd854, 0x4a3e, \
    { 0xbc, 0x2e, 0xfd, 0xf5, 0xac, 0x4a, 0x00, 0x00 } \
}
struct IDisplay_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetWidth)(IDisplay *pThis, PRUint32 *width);

    nsresult PR_COM_METHOD (*GetHeight)(IDisplay *pThis, PRUint32 *height);

    nsresult PR_COM_METHOD (*GetBitsPerPixel)(IDisplay *pThis, PRUint32 *bitsPerPixel);

    nsresult PR_COM_METHOD (*SetFramebuffer)(
        IDisplay *pThis,
        PRUint32 screenId,
        IFramebuffer * framebuffer
    );

    nsresult PR_COM_METHOD (*GetFramebuffer)(
        IDisplay *pThis,
        PRUint32 screenId,
        IFramebuffer * * framebuffer,
        PRInt32 * xOrigin,
        PRInt32 * yOrigin
    );

    nsresult PR_COM_METHOD (*SetVideoModeHint)(
        IDisplay *pThis,
        PRUint32 width,
        PRUint32 height,
        PRUint32 bitsPerPixel,
        PRUint32 display
    );

    nsresult PR_COM_METHOD (*SetSeamlessMode)(
        IDisplay *pThis,
        PRBool enabled
    );

    nsresult PR_COM_METHOD (*TakeScreenShot)(
        IDisplay *pThis,
        PRUint8 * address,
        PRUint32 width,
        PRUint32 height
    );

    nsresult PR_COM_METHOD (*TakeScreenShotSlow)(
        IDisplay *pThis,
        PRUint32 width,
        PRUint32 height,
        PRUint32 *screenDataSize,
        PRUint8** screenData
    );

    nsresult PR_COM_METHOD (*DrawToScreen)(
        IDisplay *pThis,
        PRUint8 * address,
        PRUint32 x,
        PRUint32 y,
        PRUint32 width,
        PRUint32 height
    );

    nsresult PR_COM_METHOD (*InvalidateAndUpdate)(IDisplay *pThis );

    nsresult PR_COM_METHOD (*ResizeCompleted)(
        IDisplay *pThis,
        PRUint32 screenId
    );

    nsresult PR_COM_METHOD (*UpdateCompleted)(IDisplay *pThis );

    nsresult PR_COM_METHOD (*CompleteVHWACommand)(
        IDisplay *pThis,
        PRUint8 * command
    );

};

struct IDisplay
{
    struct IDisplay_vtbl *vtbl;
};
/* End of struct IDisplay Declaration */


/* Start of struct INetworkAdapter Declaration */
#  define INETWORKADAPTER_IID_STR "65607a27-2b73-4d43-b4cc-0ba2c817fbde"
#  define INETWORKADAPTER_IID { \
    0x65607a27, 0x2b73, 0x4d43, \
    { 0xb4, 0xcc, 0x0b, 0xa2, 0xc8, 0x17, 0xfb, 0xde } \
}
struct INetworkAdapter_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetAdapterType)(INetworkAdapter *pThis, PRUint32 *adapterType);
    nsresult PR_COM_METHOD (*SetAdapterType)(INetworkAdapter *pThis, PRUint32 adapterType);

    nsresult PR_COM_METHOD (*GetSlot)(INetworkAdapter *pThis, PRUint32 *slot);

    nsresult PR_COM_METHOD (*GetEnabled)(INetworkAdapter *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(INetworkAdapter *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetMACAddress)(INetworkAdapter *pThis, PRUnichar * *MACAddress);
    nsresult PR_COM_METHOD (*SetMACAddress)(INetworkAdapter *pThis, PRUnichar * MACAddress);

    nsresult PR_COM_METHOD (*GetAttachmentType)(INetworkAdapter *pThis, PRUint32 *attachmentType);

    nsresult PR_COM_METHOD (*GetHostInterface)(INetworkAdapter *pThis, PRUnichar * *hostInterface);
    nsresult PR_COM_METHOD (*SetHostInterface)(INetworkAdapter *pThis, PRUnichar * hostInterface);

    nsresult PR_COM_METHOD (*GetInternalNetwork)(INetworkAdapter *pThis, PRUnichar * *internalNetwork);
    nsresult PR_COM_METHOD (*SetInternalNetwork)(INetworkAdapter *pThis, PRUnichar * internalNetwork);

    nsresult PR_COM_METHOD (*GetNATNetwork)(INetworkAdapter *pThis, PRUnichar * *NATNetwork);
    nsresult PR_COM_METHOD (*SetNATNetwork)(INetworkAdapter *pThis, PRUnichar * NATNetwork);

    nsresult PR_COM_METHOD (*GetCableConnected)(INetworkAdapter *pThis, PRBool *cableConnected);
    nsresult PR_COM_METHOD (*SetCableConnected)(INetworkAdapter *pThis, PRBool cableConnected);

    nsresult PR_COM_METHOD (*GetLineSpeed)(INetworkAdapter *pThis, PRUint32 *lineSpeed);
    nsresult PR_COM_METHOD (*SetLineSpeed)(INetworkAdapter *pThis, PRUint32 lineSpeed);

    nsresult PR_COM_METHOD (*GetTraceEnabled)(INetworkAdapter *pThis, PRBool *traceEnabled);
    nsresult PR_COM_METHOD (*SetTraceEnabled)(INetworkAdapter *pThis, PRBool traceEnabled);

    nsresult PR_COM_METHOD (*GetTraceFile)(INetworkAdapter *pThis, PRUnichar * *traceFile);
    nsresult PR_COM_METHOD (*SetTraceFile)(INetworkAdapter *pThis, PRUnichar * traceFile);

    nsresult PR_COM_METHOD (*AttachToNAT)(INetworkAdapter *pThis );

    nsresult PR_COM_METHOD (*AttachToBridgedInterface)(INetworkAdapter *pThis );

    nsresult PR_COM_METHOD (*AttachToInternalNetwork)(INetworkAdapter *pThis );

    nsresult PR_COM_METHOD (*AttachToHostOnlyInterface)(INetworkAdapter *pThis );

    nsresult PR_COM_METHOD (*Detach)(INetworkAdapter *pThis );

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

    nsresult PR_COM_METHOD (*GetSlot)(ISerialPort *pThis, PRUint32 *slot);

    nsresult PR_COM_METHOD (*GetEnabled)(ISerialPort *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(ISerialPort *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetIOBase)(ISerialPort *pThis, PRUint32 *IOBase);
    nsresult PR_COM_METHOD (*SetIOBase)(ISerialPort *pThis, PRUint32 IOBase);

    nsresult PR_COM_METHOD (*GetIRQ)(ISerialPort *pThis, PRUint32 *IRQ);
    nsresult PR_COM_METHOD (*SetIRQ)(ISerialPort *pThis, PRUint32 IRQ);

    nsresult PR_COM_METHOD (*GetHostMode)(ISerialPort *pThis, PRUint32 *hostMode);
    nsresult PR_COM_METHOD (*SetHostMode)(ISerialPort *pThis, PRUint32 hostMode);

    nsresult PR_COM_METHOD (*GetServer)(ISerialPort *pThis, PRBool *server);
    nsresult PR_COM_METHOD (*SetServer)(ISerialPort *pThis, PRBool server);

    nsresult PR_COM_METHOD (*GetPath)(ISerialPort *pThis, PRUnichar * *path);
    nsresult PR_COM_METHOD (*SetPath)(ISerialPort *pThis, PRUnichar * path);

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

    nsresult PR_COM_METHOD (*GetSlot)(IParallelPort *pThis, PRUint32 *slot);

    nsresult PR_COM_METHOD (*GetEnabled)(IParallelPort *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(IParallelPort *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetIOBase)(IParallelPort *pThis, PRUint32 *IOBase);
    nsresult PR_COM_METHOD (*SetIOBase)(IParallelPort *pThis, PRUint32 IOBase);

    nsresult PR_COM_METHOD (*GetIRQ)(IParallelPort *pThis, PRUint32 *IRQ);
    nsresult PR_COM_METHOD (*SetIRQ)(IParallelPort *pThis, PRUint32 IRQ);

    nsresult PR_COM_METHOD (*GetPath)(IParallelPort *pThis, PRUnichar * *path);
    nsresult PR_COM_METHOD (*SetPath)(IParallelPort *pThis, PRUnichar * path);

};

struct IParallelPort
{
    struct IParallelPort_vtbl *vtbl;
};
/* End of struct IParallelPort Declaration */


/* Start of struct IMachineDebugger Declaration */
#  define IMACHINEDEBUGGER_IID_STR "b0b2a2dd-0627-4502-91c2-ddc5e77609e0"
#  define IMACHINEDEBUGGER_IID { \
    0xb0b2a2dd, 0x0627, 0x4502, \
    { 0x91, 0xc2, 0xdd, 0xc5, 0xe7, 0x76, 0x09, 0xe0 } \
}
struct IMachineDebugger_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetSinglestep)(IMachineDebugger *pThis, PRBool *singlestep);
    nsresult PR_COM_METHOD (*SetSinglestep)(IMachineDebugger *pThis, PRBool singlestep);

    nsresult PR_COM_METHOD (*GetRecompileUser)(IMachineDebugger *pThis, PRBool *recompileUser);
    nsresult PR_COM_METHOD (*SetRecompileUser)(IMachineDebugger *pThis, PRBool recompileUser);

    nsresult PR_COM_METHOD (*GetRecompileSupervisor)(IMachineDebugger *pThis, PRBool *recompileSupervisor);
    nsresult PR_COM_METHOD (*SetRecompileSupervisor)(IMachineDebugger *pThis, PRBool recompileSupervisor);

    nsresult PR_COM_METHOD (*GetPATMEnabled)(IMachineDebugger *pThis, PRBool *PATMEnabled);
    nsresult PR_COM_METHOD (*SetPATMEnabled)(IMachineDebugger *pThis, PRBool PATMEnabled);

    nsresult PR_COM_METHOD (*GetCSAMEnabled)(IMachineDebugger *pThis, PRBool *CSAMEnabled);
    nsresult PR_COM_METHOD (*SetCSAMEnabled)(IMachineDebugger *pThis, PRBool CSAMEnabled);

    nsresult PR_COM_METHOD (*GetLogEnabled)(IMachineDebugger *pThis, PRBool *logEnabled);
    nsresult PR_COM_METHOD (*SetLogEnabled)(IMachineDebugger *pThis, PRBool logEnabled);

    nsresult PR_COM_METHOD (*GetHWVirtExEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExEnabled);

    nsresult PR_COM_METHOD (*GetHWVirtExNestedPagingEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExNestedPagingEnabled);

    nsresult PR_COM_METHOD (*GetHWVirtExVPIDEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExVPIDEnabled);

    nsresult PR_COM_METHOD (*GetPAEEnabled)(IMachineDebugger *pThis, PRBool *PAEEnabled);

    nsresult PR_COM_METHOD (*GetVirtualTimeRate)(IMachineDebugger *pThis, PRUint32 *virtualTimeRate);
    nsresult PR_COM_METHOD (*SetVirtualTimeRate)(IMachineDebugger *pThis, PRUint32 virtualTimeRate);

    nsresult PR_COM_METHOD (*GetVM)(IMachineDebugger *pThis, PRUint64 *VM);

    nsresult PR_COM_METHOD (*ResetStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern
    );

    nsresult PR_COM_METHOD (*DumpStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern
    );

    nsresult PR_COM_METHOD (*GetStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern,
        PRBool withDescriptions,
        PRUnichar * * stats
    );

    nsresult PR_COM_METHOD (*InjectNMI)(IMachineDebugger *pThis );

};

struct IMachineDebugger
{
    struct IMachineDebugger_vtbl *vtbl;
};
/* End of struct IMachineDebugger Declaration */


/* Start of struct IUSBController Declaration */
#  define IUSBCONTROLLER_IID_STR "238540fa-4b73-435a-a38e-4e1d9eab5c17"
#  define IUSBCONTROLLER_IID { \
    0x238540fa, 0x4b73, 0x435a, \
    { 0xa3, 0x8e, 0x4e, 0x1d, 0x9e, 0xab, 0x5c, 0x17 } \
}
struct IUSBController_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetEnabled)(IUSBController *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(IUSBController *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetEnabledEhci)(IUSBController *pThis, PRBool *enabledEhci);
    nsresult PR_COM_METHOD (*SetEnabledEhci)(IUSBController *pThis, PRBool enabledEhci);

    nsresult PR_COM_METHOD (*GetUSBStandard)(IUSBController *pThis, PRUint16 *USBStandard);

    nsresult PR_COM_METHOD (*GetDeviceFilters)(IUSBController *pThis, PRUint32 *deviceFiltersSize, IUSBDeviceFilter * **deviceFilters);

    nsresult PR_COM_METHOD (*CreateDeviceFilter)(
        IUSBController *pThis,
        PRUnichar * name,
        IUSBDeviceFilter * * filter
    );

    nsresult PR_COM_METHOD (*InsertDeviceFilter)(
        IUSBController *pThis,
        PRUint32 position,
        IUSBDeviceFilter * filter
    );

    nsresult PR_COM_METHOD (*RemoveDeviceFilter)(
        IUSBController *pThis,
        PRUint32 position,
        IUSBDeviceFilter * * filter
    );

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

    nsresult PR_COM_METHOD (*GetId)(IUSBDevice *pThis, PRUnichar * *id);

    nsresult PR_COM_METHOD (*GetVendorId)(IUSBDevice *pThis, PRUint16 *vendorId);

    nsresult PR_COM_METHOD (*GetProductId)(IUSBDevice *pThis, PRUint16 *productId);

    nsresult PR_COM_METHOD (*GetRevision)(IUSBDevice *pThis, PRUint16 *revision);

    nsresult PR_COM_METHOD (*GetManufacturer)(IUSBDevice *pThis, PRUnichar * *manufacturer);

    nsresult PR_COM_METHOD (*GetProduct)(IUSBDevice *pThis, PRUnichar * *product);

    nsresult PR_COM_METHOD (*GetSerialNumber)(IUSBDevice *pThis, PRUnichar * *serialNumber);

    nsresult PR_COM_METHOD (*GetAddress)(IUSBDevice *pThis, PRUnichar * *address);

    nsresult PR_COM_METHOD (*GetPort)(IUSBDevice *pThis, PRUint16 *port);

    nsresult PR_COM_METHOD (*GetVersion)(IUSBDevice *pThis, PRUint16 *version);

    nsresult PR_COM_METHOD (*GetPortVersion)(IUSBDevice *pThis, PRUint16 *portVersion);

    nsresult PR_COM_METHOD (*GetRemote)(IUSBDevice *pThis, PRBool *remote);

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

    nsresult PR_COM_METHOD (*GetName)(IUSBDeviceFilter *pThis, PRUnichar * *name);
    nsresult PR_COM_METHOD (*SetName)(IUSBDeviceFilter *pThis, PRUnichar * name);

    nsresult PR_COM_METHOD (*GetActive)(IUSBDeviceFilter *pThis, PRBool *active);
    nsresult PR_COM_METHOD (*SetActive)(IUSBDeviceFilter *pThis, PRBool active);

    nsresult PR_COM_METHOD (*GetVendorId)(IUSBDeviceFilter *pThis, PRUnichar * *vendorId);
    nsresult PR_COM_METHOD (*SetVendorId)(IUSBDeviceFilter *pThis, PRUnichar * vendorId);

    nsresult PR_COM_METHOD (*GetProductId)(IUSBDeviceFilter *pThis, PRUnichar * *productId);
    nsresult PR_COM_METHOD (*SetProductId)(IUSBDeviceFilter *pThis, PRUnichar * productId);

    nsresult PR_COM_METHOD (*GetRevision)(IUSBDeviceFilter *pThis, PRUnichar * *revision);
    nsresult PR_COM_METHOD (*SetRevision)(IUSBDeviceFilter *pThis, PRUnichar * revision);

    nsresult PR_COM_METHOD (*GetManufacturer)(IUSBDeviceFilter *pThis, PRUnichar * *manufacturer);
    nsresult PR_COM_METHOD (*SetManufacturer)(IUSBDeviceFilter *pThis, PRUnichar * manufacturer);

    nsresult PR_COM_METHOD (*GetProduct)(IUSBDeviceFilter *pThis, PRUnichar * *product);
    nsresult PR_COM_METHOD (*SetProduct)(IUSBDeviceFilter *pThis, PRUnichar * product);

    nsresult PR_COM_METHOD (*GetSerialNumber)(IUSBDeviceFilter *pThis, PRUnichar * *serialNumber);
    nsresult PR_COM_METHOD (*SetSerialNumber)(IUSBDeviceFilter *pThis, PRUnichar * serialNumber);

    nsresult PR_COM_METHOD (*GetPort)(IUSBDeviceFilter *pThis, PRUnichar * *port);
    nsresult PR_COM_METHOD (*SetPort)(IUSBDeviceFilter *pThis, PRUnichar * port);

    nsresult PR_COM_METHOD (*GetRemote)(IUSBDeviceFilter *pThis, PRUnichar * *remote);
    nsresult PR_COM_METHOD (*SetRemote)(IUSBDeviceFilter *pThis, PRUnichar * remote);

    nsresult PR_COM_METHOD (*GetMaskedInterfaces)(IUSBDeviceFilter *pThis, PRUint32 *maskedInterfaces);
    nsresult PR_COM_METHOD (*SetMaskedInterfaces)(IUSBDeviceFilter *pThis, PRUint32 maskedInterfaces);

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

    nsresult PR_COM_METHOD (*GetState)(IHostUSBDevice *pThis, PRUint32 *state);

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

    nsresult PR_COM_METHOD (*GetAction)(IHostUSBDeviceFilter *pThis, PRUint32 *action);
    nsresult PR_COM_METHOD (*SetAction)(IHostUSBDeviceFilter *pThis, PRUint32 action);

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

    nsresult PR_COM_METHOD (*GetEnabled)(IAudioAdapter *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(IAudioAdapter *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetAudioController)(IAudioAdapter *pThis, PRUint32 *audioController);
    nsresult PR_COM_METHOD (*SetAudioController)(IAudioAdapter *pThis, PRUint32 audioController);

    nsresult PR_COM_METHOD (*GetAudioDriver)(IAudioAdapter *pThis, PRUint32 *audioDriver);
    nsresult PR_COM_METHOD (*SetAudioDriver)(IAudioAdapter *pThis, PRUint32 audioDriver);

};

struct IAudioAdapter
{
    struct IAudioAdapter_vtbl *vtbl;
};
/* End of struct IAudioAdapter Declaration */


/* Start of struct IVRDPServer Declaration */
#  define IVRDPSERVER_IID_STR "72e671bc-1712-4052-ad6b-e45e76d9d3e4"
#  define IVRDPSERVER_IID { \
    0x72e671bc, 0x1712, 0x4052, \
    { 0xad, 0x6b, 0xe4, 0x5e, 0x76, 0xd9, 0xd3, 0xe4 } \
}
struct IVRDPServer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetEnabled)(IVRDPServer *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(IVRDPServer *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetPorts)(IVRDPServer *pThis, PRUnichar * *ports);
    nsresult PR_COM_METHOD (*SetPorts)(IVRDPServer *pThis, PRUnichar * ports);

    nsresult PR_COM_METHOD (*GetNetAddress)(IVRDPServer *pThis, PRUnichar * *netAddress);
    nsresult PR_COM_METHOD (*SetNetAddress)(IVRDPServer *pThis, PRUnichar * netAddress);

    nsresult PR_COM_METHOD (*GetAuthType)(IVRDPServer *pThis, PRUint32 *authType);
    nsresult PR_COM_METHOD (*SetAuthType)(IVRDPServer *pThis, PRUint32 authType);

    nsresult PR_COM_METHOD (*GetAuthTimeout)(IVRDPServer *pThis, PRUint32 *authTimeout);
    nsresult PR_COM_METHOD (*SetAuthTimeout)(IVRDPServer *pThis, PRUint32 authTimeout);

    nsresult PR_COM_METHOD (*GetAllowMultiConnection)(IVRDPServer *pThis, PRBool *allowMultiConnection);
    nsresult PR_COM_METHOD (*SetAllowMultiConnection)(IVRDPServer *pThis, PRBool allowMultiConnection);

    nsresult PR_COM_METHOD (*GetReuseSingleConnection)(IVRDPServer *pThis, PRBool *reuseSingleConnection);
    nsresult PR_COM_METHOD (*SetReuseSingleConnection)(IVRDPServer *pThis, PRBool reuseSingleConnection);

};

struct IVRDPServer
{
    struct IVRDPServer_vtbl *vtbl;
};
/* End of struct IVRDPServer Declaration */


/* Start of struct ISharedFolder Declaration */
#  define ISHAREDFOLDER_IID_STR "64637bb2-9e17-471c-b8f3-f8968dd9884e"
#  define ISHAREDFOLDER_IID { \
    0x64637bb2, 0x9e17, 0x471c, \
    { 0xb8, 0xf3, 0xf8, 0x96, 0x8d, 0xd9, 0x88, 0x4e } \
}
struct ISharedFolder_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetName)(ISharedFolder *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetHostPath)(ISharedFolder *pThis, PRUnichar * *hostPath);

    nsresult PR_COM_METHOD (*GetAccessible)(ISharedFolder *pThis, PRBool *accessible);

    nsresult PR_COM_METHOD (*GetWritable)(ISharedFolder *pThis, PRBool *writable);

    nsresult PR_COM_METHOD (*GetLastAccessError)(ISharedFolder *pThis, PRUnichar * *lastAccessError);

};

struct ISharedFolder
{
    struct ISharedFolder_vtbl *vtbl;
};
/* End of struct ISharedFolder Declaration */


/* Start of struct IInternalSessionControl Declaration */
#  define IINTERNALSESSIONCONTROL_IID_STR "f9aac6d0-41b3-46b7-bea4-6370b4036de6"
#  define IINTERNALSESSIONCONTROL_IID { \
    0xf9aac6d0, 0x41b3, 0x46b7, \
    { 0xbe, 0xa4, 0x63, 0x70, 0xb4, 0x03, 0x6d, 0xe6 } \
}
struct IInternalSessionControl_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetPID)(
        IInternalSessionControl *pThis,
        PRUint32 * pid
    );

    nsresult PR_COM_METHOD (*GetRemoteConsole)(
        IInternalSessionControl *pThis,
        IConsole * * console
    );

    nsresult PR_COM_METHOD (*AssignMachine)(
        IInternalSessionControl *pThis,
        IMachine * machine
    );

    nsresult PR_COM_METHOD (*AssignRemoteMachine)(
        IInternalSessionControl *pThis,
        IMachine * machine,
        IConsole * console
    );

    nsresult PR_COM_METHOD (*UpdateMachineState)(
        IInternalSessionControl *pThis,
        PRUint32 aMachineState
    );

    nsresult PR_COM_METHOD (*Uninitialize)(IInternalSessionControl *pThis );

    nsresult PR_COM_METHOD (*OnNetworkAdapterChange)(
        IInternalSessionControl *pThis,
        INetworkAdapter * networkAdapter,
        PRBool changeAdapter
    );

    nsresult PR_COM_METHOD (*OnSerialPortChange)(
        IInternalSessionControl *pThis,
        ISerialPort * serialPort
    );

    nsresult PR_COM_METHOD (*OnParallelPortChange)(
        IInternalSessionControl *pThis,
        IParallelPort * parallelPort
    );

    nsresult PR_COM_METHOD (*OnStorageControllerChange)(IInternalSessionControl *pThis );

    nsresult PR_COM_METHOD (*OnMediumChange)(
        IInternalSessionControl *pThis,
        IMediumAttachment * mediumAttachment,
        PRBool force
    );

    nsresult PR_COM_METHOD (*OnVRDPServerChange)(IInternalSessionControl *pThis );

    nsresult PR_COM_METHOD (*OnUSBControllerChange)(IInternalSessionControl *pThis );

    nsresult PR_COM_METHOD (*OnSharedFolderChange)(
        IInternalSessionControl *pThis,
        PRBool global
    );

    nsresult PR_COM_METHOD (*OnUSBDeviceAttach)(
        IInternalSessionControl *pThis,
        IUSBDevice * device,
        IVirtualBoxErrorInfo * error,
        PRUint32 maskedInterfaces
    );

    nsresult PR_COM_METHOD (*OnUSBDeviceDetach)(
        IInternalSessionControl *pThis,
        PRUnichar * id,
        IVirtualBoxErrorInfo * error
    );

    nsresult PR_COM_METHOD (*OnShowWindow)(
        IInternalSessionControl *pThis,
        PRBool check,
        PRBool * canShow,
        PRUint64 * winId
    );

    nsresult PR_COM_METHOD (*AccessGuestProperty)(
        IInternalSessionControl *pThis,
        PRUnichar * name,
        PRUnichar * value,
        PRUnichar * flags,
        PRBool isSetter,
        PRUnichar * * retValue,
        PRUint64 * retTimestamp,
        PRUnichar * * retFlags
    );

    nsresult PR_COM_METHOD (*EnumerateGuestProperties)(
        IInternalSessionControl *pThis,
        PRUnichar * patterns,
        PRUint32 *keySize,
        PRUnichar *** key,
        PRUint32 *valueSize,
        PRUnichar *** value,
        PRUint32 *timestampSize,
        PRUint64* timestamp,
        PRUint32 *flagsSize,
        PRUnichar *** flags
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

    nsresult PR_COM_METHOD (*GetState)(ISession *pThis, PRUint32 *state);

    nsresult PR_COM_METHOD (*GetType)(ISession *pThis, PRUint32 *type);

    nsresult PR_COM_METHOD (*GetMachine)(ISession *pThis, IMachine * *machine);

    nsresult PR_COM_METHOD (*GetConsole)(ISession *pThis, IConsole * *console);

    nsresult PR_COM_METHOD (*Close)(ISession *pThis );

};

struct ISession
{
    struct ISession_vtbl *vtbl;
};
/* End of struct ISession Declaration */


/* Start of struct IStorageController Declaration */
#  define ISTORAGECONTROLLER_IID_STR "6bf8335b-d14a-44a5-9b45-ddc49ce7d5b2"
#  define ISTORAGECONTROLLER_IID { \
    0x6bf8335b, 0xd14a, 0x44a5, \
    { 0x9b, 0x45, 0xdd, 0xc4, 0x9c, 0xe7, 0xd5, 0xb2 } \
}
struct IStorageController_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetName)(IStorageController *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetMaxDevicesPerPortCount)(IStorageController *pThis, PRUint32 *maxDevicesPerPortCount);

    nsresult PR_COM_METHOD (*GetMinPortCount)(IStorageController *pThis, PRUint32 *minPortCount);

    nsresult PR_COM_METHOD (*GetMaxPortCount)(IStorageController *pThis, PRUint32 *maxPortCount);

    nsresult PR_COM_METHOD (*GetInstance)(IStorageController *pThis, PRUint32 *instance);
    nsresult PR_COM_METHOD (*SetInstance)(IStorageController *pThis, PRUint32 instance);

    nsresult PR_COM_METHOD (*GetPortCount)(IStorageController *pThis, PRUint32 *portCount);
    nsresult PR_COM_METHOD (*SetPortCount)(IStorageController *pThis, PRUint32 portCount);

    nsresult PR_COM_METHOD (*GetBus)(IStorageController *pThis, PRUint32 *bus);

    nsresult PR_COM_METHOD (*GetControllerType)(IStorageController *pThis, PRUint32 *controllerType);
    nsresult PR_COM_METHOD (*SetControllerType)(IStorageController *pThis, PRUint32 controllerType);

    nsresult PR_COM_METHOD (*GetIDEEmulationPort)(
        IStorageController *pThis,
        PRInt32 devicePosition,
        PRInt32 * portNumber
    );

    nsresult PR_COM_METHOD (*SetIDEEmulationPort)(
        IStorageController *pThis,
        PRInt32 devicePosition,
        PRInt32 portNumber
    );

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

    nsresult PR_COM_METHOD (*GetMetricName)(IPerformanceMetric *pThis, PRUnichar * *metricName);

    nsresult PR_COM_METHOD (*GetObject)(IPerformanceMetric *pThis, nsISupports * *object);

    nsresult PR_COM_METHOD (*GetDescription)(IPerformanceMetric *pThis, PRUnichar * *description);

    nsresult PR_COM_METHOD (*GetPeriod)(IPerformanceMetric *pThis, PRUint32 *period);

    nsresult PR_COM_METHOD (*GetCount)(IPerformanceMetric *pThis, PRUint32 *count);

    nsresult PR_COM_METHOD (*GetUnit)(IPerformanceMetric *pThis, PRUnichar * *unit);

    nsresult PR_COM_METHOD (*GetMinimumValue)(IPerformanceMetric *pThis, PRInt32 *minimumValue);

    nsresult PR_COM_METHOD (*GetMaximumValue)(IPerformanceMetric *pThis, PRInt32 *maximumValue);

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

    nsresult PR_COM_METHOD (*GetMetricNames)(IPerformanceCollector *pThis, PRUint32 *metricNamesSize, PRUnichar * **metricNames);

    nsresult PR_COM_METHOD (*GetMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *metricsSize,
        IPerformanceMetric *** metrics
    );

    nsresult PR_COM_METHOD (*SetupMetrics)(
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

    nsresult PR_COM_METHOD (*EnableMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *affectedMetricsSize,
        IPerformanceMetric *** affectedMetrics
    );

    nsresult PR_COM_METHOD (*DisableMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *affectedMetricsSize,
        IPerformanceMetric *** affectedMetrics
    );

    nsresult PR_COM_METHOD (*QueryMetricsData)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *returnMetricNamesSize,
        PRUnichar *** returnMetricNames,
        PRUint32 *returnObjectsSize,
        nsISupports ** returnObjects,
        PRUint32 *returnUnitsSize,
        PRUnichar *** returnUnits,
        PRUint32 *returnScalesSize,
        PRUint32* returnScales,
        PRUint32 *returnSequenceNumbersSize,
        PRUint32* returnSequenceNumbers,
        PRUint32 *returnDataIndicesSize,
        PRUint32* returnDataIndices,
        PRUint32 *returnDataLengthsSize,
        PRUint32* returnDataLengths,
        PRUint32 *returnDataSize,
        PRInt32** returnData
    );

};

struct IPerformanceCollector
{
    struct IPerformanceCollector_vtbl *vtbl;
};
/* End of struct IPerformanceCollector Declaration */



#  define NS_VIRTUALBOX_CID { \
    0xB1A7A4F2, 0x47B9, 0x4A1E, \
    { 0x82, 0xB2, 0x07, 0xCC, 0xD5, 0x32, 0x3C, 0x3F } \
}
#  define NS_VIRTUALBOX_CONTRACTID "@virtualbox.org/VirtualBox;1"
/* for compatibility with Win32 */
#  define CLSID_VirtualBox (nsCID) NS_VIRTUALBOX_CID



#  define NS_SESSION_CID { \
    0x3C02F46D, 0xC9D2, 0x4F11, \
    { 0xA3, 0x84, 0x53, 0xF0, 0xCF, 0x91, 0x72, 0x14 } \
}
#  define NS_SESSION_CONTRACTID "@virtualbox.org/Session;1"
/* for compatibility with Win32 */
#  define CLSID_Session (nsCID) NS_SESSION_CID



#  define NS_CALLBACKWRAPPER_CID { \
    0x49EE8561, 0x5563, 0x4715, \
    { 0xB1, 0x8C, 0xA4, 0xB1, 0xA4, 0x90, 0xDA, 0xFE } \
}
#  define NS_CALLBACKWRAPPER_CONTRACTID "@virtualbox.org/CallbackWrapper;1"
/* for compatibility with Win32 */
#  define CLSID_CallbackWrapper (nsCID) NS_CALLBACKWRAPPER_CID



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

    unsigned int (*pfnGetVersion)(void);

    void  (*pfnComInitialize)(const char *pszVirtualBoxIID,
                              IVirtualBox **ppVirtualBox,
                              const char *pszSessionIID,
                              ISession **ppSession);
    void (*pfnComUninitialize)(void);

    void  (*pfnComUnallocMem)(void *pv);
    void  (*pfnUtf16Free)(PRUnichar *pwszString);
    void  (*pfnUtf8Free)(char *pszString);

    int   (*pfnUtf16ToUtf8)(const PRUnichar *pwszString, char **ppszString);
    int   (*pfnUtf8ToUtf16)(const char *pszString, PRUnichar **ppwszString);

    void  (*pfnGetEventQueue)(nsIEventQueue **eventQueue);

    /** Tail version, same as uVersion. */
    unsigned uEndVersion;
} VBOXXPCOMC;
/** Pointer to a const VBoxXPCOMC function table. */
typedef VBOXXPCOMC const *PCVBOXXPCOM;

/** The current interface version.
 * For use with VBoxGetXPCOMCFunctions and to be found in
 * VBOXXPCOMC::uVersion. */
# define VBOX_XPCOMC_VERSION     0x00020000U

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
