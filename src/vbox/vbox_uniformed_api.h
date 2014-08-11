/*
 * Copyright 2014, Taowei Luo (uaedante@gmail.com)
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef VBOX_UNIFORMED_API_H
# define VBOX_UNIFORMED_API_H

# include "internal.h"

/* This file may be used in three place. That is vbox_tmpl.c,
 * vbox_common.c and vbox_driver.c. The vboxUniformedAPI and some
 * types used for vboxUniformedAPI is defined here.
 *
 * The vbox_tmpl.c is the only place where the driver knows the inside
 * architecture of those vbox structs(vboxObj, vboxSession,
 * pFuncs, vboxCallback and vboxQueue). The file should be included
 * after the currect vbox_CAPI_v*.h, then we can use the vbox structs
 * in vboxGlobalData. The vbox_tmpl.c should implement functions
 * defined in vboxUniformedAPI.
 *
 * In vbox_driver.c, it is used to define the struct vboxUniformedAPI.
 * The vbox_driver.c collects vboxUniformedAPI for all versions.
 * Then vboxRegister calls the vboxRegisterUniformedAPI to register.
 * Note: In vbox_driver.c, the vbox structs in vboxGlobalData is
 * defined by vbox_CAPI_v2.2.h.
 *
 * The vbox_common.c, it is used to generate common codes for all vbox
 * versions. Bacause the same member varible's offset in a vbox struct
 * may change between different vbox versions. The vbox_common.c
 * shouldn't directly use struct's member varibles defined in
 * vbox_CAPI_v*.h. To make things safety, we include the
 * vbox_common.h in vbox_common.c. In this case, we treat structs
 * defined by vbox as a void*. The common codes don't concern about
 * the inside of this structs(actually, we can't, in the common level).
 * With the help of vboxUniformed API, we call VirtualBox's API and
 * implement the vbox driver in a high level.
 *
 * In conclusion:
 *  * In vbox_tmpl.c, this file is included after vbox_CAPI_v*.h
 *  * In vbox_driver.c, this file is included after vbox_glue.h
 *  * In vbox_common.c, this file is included after vbox_common.h
 *
 */

/* Extracted define from vbox_tmpl.c */

# ifdef WIN32
struct _vboxIID_v2_x_WIN32 {
    /* IID is represented by a GUID value. */
    GUID value;
};
# endif /* !WIN32 */

struct _vboxIID_v2_x {
    /* IID is represented by a pointer to a nsID. */
    nsID *value;

    /* backing is used in cases where we need to create or copy an IID.
     * We cannot allocate memory that can be freed by ComUnallocMem.
     * Therefore, we use this stack allocated nsID instead. */
    nsID backing;
};

struct _vboxIID_v3_x {
    /* IID is represented by a UTF-16 encoded UUID in string form. */
    PRUnichar *value;

    /* owner indicates if we own the value and need to free it. */
    bool owner;
};

typedef union {
# ifdef WIN32
    struct _vboxIID_v2_x_WIN32 vboxIID_v2_x_WIN32;
# endif /* !WIN32 */
    struct _vboxIID_v2_x vboxIID_v2_x;
    struct _vboxIID_v3_x vboxIID_v3_x;
} vboxIIDUnion;

typedef union {
    nsresult uResultCode;
    PRInt32 resultCode;
} resultCodeUnion;

typedef struct {
    virMutex lock;
    unsigned long version;

    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;

    IVirtualBox *vboxObj;
    ISession *vboxSession;

    /** Our version specific API table pointer. */
    PCVBOXXPCOM pFuncs;

    /* The next is used for domainEvent */
# if defined(VBOX_API_VERSION) && VBOX_API_VERSION > 2002000 && VBOX_API_VERSION < 4000000

    /* Async event handling */
    virObjectEventStatePtr domainEvents;
    int fdWatch;
    IVirtualBoxCallback *vboxCallback;
    nsIEventQueue  *vboxQueue;

    int volatile vboxCallBackRefCount;

    /* pointer back to the connection */
    virConnectPtr conn;

# else /* VBOX_API_VERSION <= 2002000 || VBOX_API_VERSION >= 4000000 || VBOX_API_VERSION undefined */

    virObjectEventStatePtr domainEvents;
    int fdWatch;
    void *vboxCallback;
    void *vboxQueue;
    int volatile vboxCallBackRefCount;
    virConnectPtr conn;

# endif /* VBOX_API_VERSION <= 2002000 || VBOX_API_VERSION >= 4000000 || VBOX_API_VERSION undefined */

} vboxGlobalData;

/* vboxUniformedAPI gives vbox_common.c a uniformed layer to see
 * vbox API.
 */

/* Functions for pFuncs */
typedef struct {
    int (*Initialize)(vboxGlobalData *data);
    void (*Uninitialize)(vboxGlobalData *data);
    void (*ComUnallocMem)(PCVBOXXPCOM pFuncs, void *pv);
    void (*Utf16Free)(PCVBOXXPCOM pFuncs, PRUnichar *pwszString);
    void (*Utf8Free)(PCVBOXXPCOM pFuncs, char *pszString);
    int (*Utf16ToUtf8)(PCVBOXXPCOM pFuncs, const PRUnichar *pwszString, char **ppszString);
    int (*Utf8ToUtf16)(PCVBOXXPCOM pFuncs, const char *pszString, PRUnichar **ppwszString);
} vboxUniformedPFN;

/* Functions for vboxIID */
typedef struct {
    void (*vboxIIDInitialize)(vboxIIDUnion *iidu);
    void (*vboxIIDUnalloc)(vboxGlobalData *data, vboxIIDUnion *iidu);
    void (*vboxIIDToUUID)(vboxGlobalData *data, vboxIIDUnion *iidu, unsigned char *uuid);
    void (*vboxIIDFromUUID)(vboxGlobalData *data, vboxIIDUnion *iidu, const unsigned char *uuid);
    bool (*vboxIIDIsEqual)(vboxGlobalData *data, vboxIIDUnion *iidu1, vboxIIDUnion *iidu2);
    void (*vboxIIDFromArrayItem)(vboxGlobalData *data, vboxIIDUnion *iidu, vboxArray *array, int idx);
    void (*DEBUGIID)(const char *msg, vboxIIDUnion *iidu);
} vboxUniformedIID;

/* Functions for nsISupports */
typedef struct {
    nsresult (*Release)(nsISupports *nsi);
} vboxUniformednsISupports;

/* Functions for IVirtualBox */
typedef struct {
    nsresult (*GetVersion)(IVirtualBox *vboxObj, PRUnichar **versionUtf16);
    nsresult (*GetMachine)(IVirtualBox *vboxObj, vboxIIDUnion *iidu, IMachine **machine);
    nsresult (*GetSystemProperties)(IVirtualBox *vboxObj, ISystemProperties **systemProperties);
} vboxUniformedIVirtualBox;

/* Functions for ISession */
typedef struct {
    nsresult (*OpenExisting)(vboxGlobalData *data, vboxIIDUnion *iidu, IMachine *machine);
    nsresult (*GetConsole)(ISession *session, IConsole **console);
    nsresult (*Close)(ISession *session);
} vboxUniformedISession;

/* Functions for IConsole */
typedef struct {
    nsresult (*SaveState)(IConsole *console, IProgress **progress);
} vboxUniformedIConsole;

/* Functions for IProgress */
typedef struct {
    nsresult (*WaitForCompletion)(IProgress *progress, PRInt32 timeout);
    nsresult (*GetResultCode)(IProgress *progress, resultCodeUnion *resultCode);
} vboxUniformedIProgress;

/* Functions for ISystemProperties */
typedef struct {
    nsresult (*GetMaxGuestCPUCount)(ISystemProperties *systemProperties, PRUint32 *maxCPUCount);
} vboxUniformedISystemProperties;

typedef struct {
    /* vbox API version */
    uint32_t APIVersion;
    uint32_t XPCOMCVersion;
    /* vbox APIs */
    int (*initializeDomainEvent)(vboxGlobalData *data);
    void (*registerGlobalData)(vboxGlobalData *data);
    vboxUniformedPFN UPFN;
    vboxUniformedIID UIID;
    vboxUniformednsISupports nsUISupports;
    vboxUniformedIVirtualBox UIVirtualBox;
    vboxUniformedISession UISession;
    vboxUniformedIConsole UIConsole;
    vboxUniformedIProgress UIProgress;
    vboxUniformedISystemProperties UISystemProperties;
    /* vbox API features */
    bool domainEventCallbacks;
    bool hasStaticGlobalData;
    bool getMachineForSession;
} vboxUniformedAPI;

/* libvirt API
 * These API would be removed after we generate the
 * vboxDriver in common code.
 */
virDrvOpenStatus vboxConnectOpen(virConnectPtr conn,
                                 virConnectAuthPtr auth,
                                 unsigned int flags);
int vboxConnectClose(virConnectPtr conn);
int vboxDomainSave(virDomainPtr dom, const char *path);
int vboxConnectGetVersion(virConnectPtr conn, unsigned long *version);
char *vboxConnectGetHostname(virConnectPtr conn);
int vboxConnectIsSecure(virConnectPtr conn);
int vboxConnectIsEncrypted(virConnectPtr conn);
int vboxConnectIsAlive(virConnectPtr conn);
int vboxConnectGetMaxVcpus(virConnectPtr conn, const char *type);
char *vboxConnectGetCapabilities(virConnectPtr conn);

/* Version specified functions for installing uniformed API */
void vbox22InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox30InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox31InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox32InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox40InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox41InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox42InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox42_20InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox43InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox43_4InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);

#endif /* VBOX_UNIFORMED_API_H */
