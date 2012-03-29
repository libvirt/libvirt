
/*
 * vbox_MSCOMGlue.c: glue to the MSCOM based VirtualBox API
 *
 * Copyright (C) 2010-2011 Matthias Bolte <matthias.bolte@googlemail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include <windows.h>

#define nsCID CLSID

#include "internal.h"
#include "memory.h"
#include "util.h"
#include "logging.h"
#include "virterror_internal.h"
#include "vbox_MSCOMGlue.h"

#define VIR_FROM_THIS VIR_FROM_VBOX

#define VBOX_REGKEY_ORACLE "Software\\Oracle\\VirtualBox"
#define VBOX_REGKEY_SUN "Software\\Sun\\xVM VirtualBox"

#define IVIRTUALBOX_IID_STR_v2_2 "779264f4-65ed-48ed-be39-518ca549e296"
#define ISESSION_IID_STR_v2_2 "12F4DCDB-12B2-4ec1-B7CD-DDD9F6C5BF4D"



typedef struct _VBOXXPCOMC_v1 VBOXXPCOMC_v1;
typedef struct _VBOXXPCOMC_v2 VBOXXPCOMC_v2;

struct _VBOXXPCOMC_v1 {
    unsigned cb;
    unsigned uVersion;
    unsigned int (*pfnGetVersion)(void);
    void (*pfnComInitialize)(IVirtualBox **virtualBox, ISession **session);
    void (*pfnComUninitialize)(void);
    void (*pfnComUnallocMem)(void *pv);
    void (*pfnUtf16Free)(PRUnichar *pwszString);
    void (*pfnUtf8Free)(char *pszString);
    int (*pfnUtf16ToUtf8)(const PRUnichar *pwszString, char **ppszString);
    int (*pfnUtf8ToUtf16)(const char *pszString, PRUnichar **ppwszString);
    unsigned uEndVersion;
};

struct _VBOXXPCOMC_v2 {
    unsigned cb;
    unsigned uVersion;
    unsigned int (*pfnGetVersion)(void);
    void (*pfnComInitialize)(const char *pszVirtualBoxIID,
                             IVirtualBox **ppVirtualBox,
                             const char *pszSessionIID,
                             ISession **ppSession);
    void (*pfnComUninitialize)(void);
    void (*pfnComUnallocMem)(void *pv);
    void (*pfnUtf16Free)(PRUnichar *pwszString);
    void (*pfnUtf8Free)(char *pszString);
    int (*pfnUtf16ToUtf8)(const PRUnichar *pwszString, char **ppszString);
    int (*pfnUtf8ToUtf16)(const char *pszString, PRUnichar **ppwszString);
    void (*pfnGetEventQueue)(nsIEventQueue **eventQueue);
    unsigned uEndVersion;
};



PFNVBOXGETXPCOMCFUNCTIONS g_pfnGetFunctions = NULL;

static unsigned long vboxVersion;
static IVirtualBox *vboxVirtualBox;
static ISession *vboxSession;



/*
 * nsISupports dummy implementation
 */

static nsresult __stdcall
vboxSupports_QueryInterface(nsISupports *pThis ATTRIBUTE_UNUSED,
                            const nsID *iid ATTRIBUTE_UNUSED,
                            void **resultp ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxSupports_AddRef(nsISupports *pThis ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxSupports_Release(nsISupports *pThis ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxSupports_GetTypeInfoCount(nsISupports *pThis ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxSupports_GetTypeInfo(nsISupports *pThis ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxSupports_GetIDsOfNames(nsISupports *pThis ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxSupports_Invoke(nsISupports *pThis ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}



/*
 * nsIEventTarget dummy implementation
 */

static nsresult __stdcall
vboxEventTarget_PostEvent(nsIEventTarget *pThis ATTRIBUTE_UNUSED,
                          PLEvent *aEvent ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventTarget_IsOnCurrentThread(nsIEventTarget *pThis ATTRIBUTE_UNUSED,
                                  PRBool *_retval ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}



/*
 * nsIEventQueue dummy implementation
 */

static nsresult __stdcall
vboxEventQueue_InitEvent(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                         PLEvent *aEvent ATTRIBUTE_UNUSED,
                         void *owner ATTRIBUTE_UNUSED,
                         PLHandleEventProc handler ATTRIBUTE_UNUSED,
                         PLDestroyEventProc destructor ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_PostSynchronousEvent(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                                    PLEvent *aEvent ATTRIBUTE_UNUSED,
                                    void **aResult ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_PendingEvents(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                             PRBool *_retval ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_ProcessPendingEvents(nsIEventQueue *pThis ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_EventLoop(nsIEventQueue *pThis ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_EventAvailable(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                              PRBool *aResult ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_GetEvent(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                        PLEvent **_retval ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_HandleEvent(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                           PLEvent *aEvent ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_WaitForEvent(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                            PLEvent **_retval ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static PRInt32 __stdcall
vboxEventQueue_GetEventQueueSelectFD(nsIEventQueue *pThis ATTRIBUTE_UNUSED)
{
    return -1;
}

static nsresult __stdcall
vboxEventQueue_Init(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                    PRBool aNative ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_InitFromPRThread(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                                PRThread *thread ATTRIBUTE_UNUSED,
                                PRBool aNative ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_InitFromPLQueue(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                               PLEventQueue *aQueue ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_EnterMonitor(nsIEventQueue *pThis ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_ExitMonitor(nsIEventQueue *pThis ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_RevokeEvents(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                            void *owner ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_GetPLEventQueue(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                               PLEventQueue **_retval ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_IsQueueNative(nsIEventQueue *pThis ATTRIBUTE_UNUSED,
                             PRBool *_retval ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static nsresult __stdcall
vboxEventQueue_StopAcceptingEvents(nsIEventQueue *pThis ATTRIBUTE_UNUSED)
{
    return NS_ERROR_NOT_IMPLEMENTED;
}

static struct nsIEventQueue_vtbl vboxEventQueueVtbl = {
    {
        {
            vboxSupports_QueryInterface,
            vboxSupports_AddRef,
            vboxSupports_Release,

            vboxSupports_GetTypeInfoCount,
            vboxSupports_GetTypeInfo,
            vboxSupports_GetIDsOfNames,
            vboxSupports_Invoke
        },

        vboxEventTarget_PostEvent,
        vboxEventTarget_IsOnCurrentThread
    },

    vboxEventQueue_InitEvent,
    vboxEventQueue_PostSynchronousEvent,
    vboxEventQueue_PendingEvents,
    vboxEventQueue_ProcessPendingEvents,
    vboxEventQueue_EventLoop,
    vboxEventQueue_EventAvailable,
    vboxEventQueue_GetEvent,
    vboxEventQueue_HandleEvent,
    vboxEventQueue_WaitForEvent,
    vboxEventQueue_GetEventQueueSelectFD,
    vboxEventQueue_Init,
    vboxEventQueue_InitFromPRThread,
    vboxEventQueue_InitFromPLQueue,
    vboxEventQueue_EnterMonitor,
    vboxEventQueue_ExitMonitor,
    vboxEventQueue_RevokeEvents,
    vboxEventQueue_GetPLEventQueue,
    vboxEventQueue_IsQueueNative,
    vboxEventQueue_StopAcceptingEvents,
};

static nsIEventQueue vboxEventQueue = {
    &vboxEventQueueVtbl
};



static char *
vboxLookupRegistryValue(HKEY key, const char *keyName, const char *valueName)
{
    LONG status;
    DWORD type;
    DWORD length;
    char *value = NULL;

    status = RegQueryValueEx(key, valueName, NULL, &type, NULL, &length);

    if (status != ERROR_SUCCESS) {
        VIR_ERROR(_("Could not query registry value '%s\\%s'"),
                  keyName, valueName);
        goto cleanup;
    }

    if (type != REG_SZ) {
        VIR_ERROR(_("Registry value '%s\\%s' has unexpected type"),
                  keyName, valueName);
        goto cleanup;
    }

    if (length < 2) {
        VIR_ERROR(_("Registry value '%s\\%s' is too short"),
                  keyName, valueName);
        goto cleanup;
    }

    /* +1 for the null-terminator if it's missing */
    if (VIR_ALLOC_N(value, length + 1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    status = RegQueryValueEx(key, valueName, NULL, NULL, (LPBYTE)value, &length);

    if (status != ERROR_SUCCESS) {
        VIR_FREE(value);
        VIR_ERROR(_("Could not query registry value '%s\\%s'"),
                  keyName, valueName);
        goto cleanup;
    }

    if (value[length - 1] != '\0') {
        value[length] = '\0';
    }

  cleanup:
    return value;
}

static int
vboxLookupVersionInRegistry(void)
{
    int result = -1;
    const char *keyName = VBOX_REGKEY_ORACLE;
    LONG status;
    HKEY key;
    char *value = NULL;

    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &key);

    if (status != ERROR_SUCCESS) {
        keyName = VBOX_REGKEY_SUN;
        status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &key);

        if (status != ERROR_SUCCESS) {
            /* Both keys aren't there, or we cannot open them. In general this
             * indicates that VirtualBox is not installed, so we just silently
             * fail here making vboxRegister() register the dummy driver. */
            return -1;
        }
    }

    /* The registry key layout changed around version 4.0.8. Before the version
     * number was in the Version key, now the Version key can contain %VER% and
     * the actual version number is in the VersionExt key then. */
    value = vboxLookupRegistryValue(key, keyName, "Version");

    if (value == NULL) {
        goto cleanup;
    }

    if (STREQ(value, "%VER%")) {
        VIR_FREE(value);
        value = vboxLookupRegistryValue(key, keyName, "VersionExt");

        if (value == NULL) {
            goto cleanup;
        }
    }

    if (virParseVersionString(value, &vboxVersion, false) < 0) {
        VIR_ERROR(_("Could not parse version number from '%s'"), value);
        goto cleanup;
    }

    result = 0;

  cleanup:
    VIR_FREE(value);
    RegCloseKey(key);

    return result;
}

static unsigned int
vboxGetVersion(void)
{
    return vboxVersion;
}

static void
vboxComUnallocMem(void *pv)
{
    SysFreeString(pv);
}

static void
vboxUtf16Free(PRUnichar *pwszString)
{
    SysFreeString(pwszString);
}

static void
vboxUtf8Free(char *pszString)
{
    VIR_FREE(pszString);
}

static int
vboxUtf16ToUtf8(const PRUnichar *pwszString, char **ppszString)
{
    int length = WideCharToMultiByte(CP_UTF8, 0, pwszString, -1, NULL, 0,
                                     NULL, NULL);

    if (length < 1) {
        return -1;
    }

    if (VIR_ALLOC_N(*ppszString, length) < 0) {
        return -1;
    }

    return WideCharToMultiByte(CP_UTF8, 0, pwszString, -1, *ppszString,
                               length, NULL, NULL);
}

static int
vboxUtf8ToUtf16(const char *pszString, PRUnichar **ppwszString)
{
    int length = MultiByteToWideChar(CP_UTF8, 0, pszString, -1, NULL, 0);

    if (length < 1) {
        return -1;
    }

    *ppwszString = SysAllocStringLen(NULL, length);

    if (*ppwszString == NULL) {
        return -1;
    }

    return MultiByteToWideChar(CP_UTF8, 0, pszString, -1, *ppwszString, length);
}

static void
vboxGetEventQueue(nsIEventQueue **eventQueue)
{
    *eventQueue = &vboxEventQueue;
}

static void
vboxComInitialize_v2(const char *pszVirtualBoxIID, IVirtualBox **ppVirtualBox,
                     const char *pszSessionIID, ISession **ppSession)
{
    int result = -1;
    HRESULT hrc;
    IID virtualBoxIID;
    IID sessionIID;
    char *mbsVirtualBoxIID = NULL;
    char *mbsSessionIID = NULL;
    PRUnichar *wcsVirtualBoxIID = NULL;
    PRUnichar *wcsSessionIID = NULL;

    *ppVirtualBox = NULL;
    *ppSession = NULL;

    CoInitialize(NULL);

    if (virAsprintf(&mbsVirtualBoxIID, "{%s}", pszVirtualBoxIID) < 0 ||
        virAsprintf(&mbsSessionIID, "{%s}", pszSessionIID) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (vboxUtf8ToUtf16(mbsVirtualBoxIID, &wcsVirtualBoxIID) < 0 ||
        vboxUtf8ToUtf16(mbsSessionIID, &wcsSessionIID) < 0) {
        goto cleanup;
    }

    hrc = IIDFromString(wcsVirtualBoxIID, &virtualBoxIID);

    if (FAILED(hrc)) {
        VIR_ERROR(_("Could not parse IID from '%s', rc = 0x%08x"),
                  pszVirtualBoxIID, (unsigned int)hrc);
        goto cleanup;
    }

    hrc = IIDFromString(wcsSessionIID, &sessionIID);

    if (FAILED(hrc)) {
        VIR_ERROR(_("Could not parse IID from '%s', rc = 0x%08x"),
                  pszVirtualBoxIID, (unsigned int)hrc);
        goto cleanup;
    }

    hrc = CoCreateInstance(&CLSID_VirtualBox, NULL, CLSCTX_LOCAL_SERVER,
                           &virtualBoxIID, (void**)&vboxVirtualBox);

    if (FAILED(hrc)) {
        VIR_ERROR(_("Could not create VirtualBox instance, rc = 0x%08x"),
                  (unsigned int)hrc);
        goto cleanup;
    }

    hrc = CoCreateInstance(&CLSID_Session, NULL, CLSCTX_INPROC_SERVER,
                           &sessionIID, (void**)&vboxSession);

    if (FAILED(hrc)) {
        VIR_ERROR(_("Could not create Session instance, rc = 0x%08x"),
                  (unsigned int)hrc);
        goto cleanup;
    }

    *ppVirtualBox = vboxVirtualBox;
    *ppSession = vboxSession;

    result = 0;

  cleanup:
    if (result < 0) {
        if (vboxVirtualBox != NULL) {
            vboxVirtualBox->vtbl->nsisupports.Release((nsISupports *)vboxVirtualBox);
            vboxVirtualBox = NULL;
        }

        if (vboxSession != NULL) {
            vboxSession->vtbl->nsisupports.Release((nsISupports *)vboxSession);
            vboxSession = NULL;
        }
    }

    vboxUtf16Free(wcsVirtualBoxIID);
    vboxUtf16Free(wcsSessionIID);
}

static void
vboxComInitialize_v1(IVirtualBox **ppVirtualBox, ISession **ppSession)
{
    vboxComInitialize_v2(IVIRTUALBOX_IID_STR_v2_2, ppVirtualBox,
                         ISESSION_IID_STR_v2_2, ppSession);
}

static void
vboxComUninitialize(void)
{
    if (vboxVirtualBox != NULL) {
        vboxVirtualBox->vtbl->nsisupports.Release((nsISupports *)vboxVirtualBox);
        vboxVirtualBox = NULL;
    }

    if (vboxSession != NULL) {
        vboxSession->vtbl->nsisupports.Release((nsISupports *)vboxSession);
        vboxSession = NULL;
    }

    CoUninitialize();
}



static VBOXXPCOMC_v1 vboxXPCOMC_v1 = {
    sizeof(VBOXXPCOMC_v1),      /* cb */
    0x00010000U,                /* uVersion */
    vboxGetVersion,             /* pfnGetVersion */
    vboxComInitialize_v1,       /* pfnComInitialize */
    vboxComUninitialize,        /* pfnComUninitialize */
    vboxComUnallocMem,          /* pfnComUnallocMem */
    vboxUtf16Free,              /* pfnUtf16Free */
    vboxUtf8Free,               /* pfnUtf8Free */
    vboxUtf16ToUtf8,            /* pfnUtf16ToUtf8 */
    vboxUtf8ToUtf16,            /* pfnUtf8ToUtf16 */
    0x00010000U                 /* uEndVersion */
};

static VBOXXPCOMC_v2 vboxXPCOMC_v2 = {
    sizeof(VBOXXPCOMC_v2),      /* cb */
    0x00020000U,                /* uVersion */
    vboxGetVersion,             /* pfnGetVersion */
    vboxComInitialize_v2,       /* pfnComInitialize */
    vboxComUninitialize,        /* pfnComUninitialize */
    vboxComUnallocMem,          /* pfnComUnallocMem */
    vboxUtf16Free,              /* pfnUtf16Free */
    vboxUtf8Free,               /* pfnUtf8Free */
    vboxUtf16ToUtf8,            /* pfnUtf16ToUtf8 */
    vboxUtf8ToUtf16,            /* pfnUtf8ToUtf16 */
    vboxGetEventQueue,          /* pfnGetEventQueue */
    0x00020000U                 /* uEndVersion */
};

static PCVBOXXPCOM
vboxGetFunctions(unsigned int version)
{
    if (version == 0x00010000U) {
        return (PCVBOXXPCOM)&vboxXPCOMC_v1;
    } else if (version == 0x00020000U) {
        return (PCVBOXXPCOM)&vboxXPCOMC_v2;
    } else {
        return NULL;
    }
}



int
VBoxCGlueInit(unsigned int *version)
{
    if (vboxLookupVersionInRegistry() < 0) {
        return -1;
    }

    *version = vboxGetVersion();
    g_pfnGetFunctions = vboxGetFunctions;

    return 0;
}

void
VBoxCGlueTerm(void)
{
}



/*
 * In MSCOM an array is represented by a SAFEARRAY pointer. To access the items
 * in the array the SafeArrayAccessData function is used to lock the array and
 * get its contents. When the items aren't needed anymore the
 * SafeArrayUnaccessData function is used to unlock the array. The pointer
 * retuned by SafeArrayAccessData function becomes invalid. Finally the
 * SafeArrayDestroy function is called to destroy the array, it also releases
 * or frees all items in the array according to their type.
 */

typedef HRESULT __stdcall (*SafeArrayGetter)(void *self, SAFEARRAY **array);
typedef HRESULT __stdcall (*SafeArrayGetterWithPtrArg)(void *self, void *arg, SAFEARRAY **array);
typedef HRESULT __stdcall (*SafeArrayGetterWithUintArg)(void *self, PRUint32 arg, SAFEARRAY **array);

static nsresult
vboxArrayGetHelper(vboxArray *array, HRESULT hrc, SAFEARRAY *safeArray)
{
    void **items = NULL;

    array->items = NULL;
    array->count = 0;
    array->handle = NULL;

    if (FAILED(hrc)) {
        return hrc;
    }

    hrc = SafeArrayAccessData(safeArray, (void **)&items);

    if (FAILED(hrc)) {
        SafeArrayDestroy(safeArray);
        return hrc;
    }

    array->items = items;
    array->count = safeArray->rgsabound[0].cElements;
    array->handle = safeArray;

    return hrc;
}

/*
 * Call the getter with self as first argument and fill the array with the
 * returned items.
 */
nsresult
vboxArrayGet(vboxArray *array, void *self, void *getter)
{
    HRESULT hrc;
    SAFEARRAY *safeArray = NULL;

    hrc = ((SafeArrayGetter)getter)(self, &safeArray);

    return vboxArrayGetHelper(array, hrc, safeArray);
}

/*
 * Call the getter with self as first argument and arg as second argument
 * and fill the array with the returned items.
 */
nsresult
vboxArrayGetWithPtrArg(vboxArray *array, void *self, void *getter, void *arg)
{
    HRESULT hrc;
    SAFEARRAY *safeArray = NULL;

    hrc = ((SafeArrayGetterWithPtrArg)getter)(self, arg, &safeArray);

    return vboxArrayGetHelper(array, hrc, safeArray);
}

/*
 * Call the getter with self as first argument and arg as second argument
 * and fill the array with the returned items.
 */
nsresult
vboxArrayGetWithUintArg(vboxArray *array, void *self, void *getter, PRUint32 arg)
{
    HRESULT hrc;
    SAFEARRAY *safeArray = NULL;

    hrc = ((SafeArrayGetterWithUintArg)getter)(self, arg, &safeArray);

    return vboxArrayGetHelper(array, hrc, safeArray);
}

/*
 * Release all items in the array and reset it.
 *
 * SafeArrayDestroy is aware of the item's type and calls release or free
 * for each item according to its type. Therefore, vboxArrayUnalloc and
 * vboxArrayRelease are the same for MSCOM.
 */
void
vboxArrayRelease(vboxArray *array)
{
    if (array->handle == NULL) {
        return;
    }

    SafeArrayUnaccessData(array->handle);
    SafeArrayDestroy(array->handle);

    array->items = NULL;
    array->count = 0;
    array->handle = NULL;
}
