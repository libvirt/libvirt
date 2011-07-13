
/*
 * hyperv_wmi.h: general WMI over WSMAN related functions and structures for
 *               managing Microsoft Hyper-V hosts
 *
 * Copyright (C) 2011 Matthias Bolte <matthias.bolte@googlemail.com>
 * Copyright (C) 2009 Michael Sievers <msievers83@googlemail.com>
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

#ifndef __HYPERV_WMI_H__
# define __HYPERV_WMI_H__

# include "buf.h"
# include "hyperv_private.h"
# include "hyperv_wmi_classes.h"
# include "openwsman.h"



typedef struct _hypervObject hypervObject;

int hyperyVerifyResponse(WsManClient *client, WsXmlDocH response,
                         const char *detail);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Object
 */

struct _hypervObject {
    XmlSerializerInfo *serializerInfo;
    XML_TYPE_PTR data;
    hypervObject *next;
};

int hypervEnumAndPull(hypervPrivate *priv, virBufferPtr query,
                      const char *root, XmlSerializerInfo *serializerInfo,
                      const char *resourceUri, const char *className,
                      hypervObject **list);

void hypervFreeObject(hypervPrivate *priv, hypervObject *object);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * CIM/Msvm_ReturnCode
 */

enum _CIM_ReturnCode {
    CIM_RETURNCODE_COMPLETED_WITH_NO_ERROR = 0,
    CIM_RETURNCODE_NOT_SUPPORTED = 1,
    CIM_RETURNCODE_UNKNOWN_ERROR = 2,
    CIM_RETURNCODE_CANNOT_COMPLETE_WITHIN_TIMEOUT_PERIOD = 3,
    CIM_RETURNCODE_FAILED = 4,
    CIM_RETURNCODE_INVALID_PARAMETER = 5,
    CIM_RETURNCODE_IN_USE = 6,
    CIM_RETURNCODE_TRANSITION_STARTED = 4096,
    CIM_RETURNCODE_INVALID_STATE_TRANSITION = 4097,
    CIM_RETURNCODE_TIMEOUT_PARAMETER_NOT_SUPPORTED = 4098,
    CIM_RETURNCODE_BUSY = 4099,
};

enum _Msvm_ReturnCode {
    MSVM_RETURNCODE_FAILED = 32768,
    MSVM_RETURNCODE_ACCESS_DENIED = 32769,
    MSVM_RETURNCODE_NOT_SUPPORTED = 32770,
    MSVM_RETURNCODE_STATUS_IS_UNKNOWN = 32771,
    MSVM_RETURNCODE_TIMEOUT = 32772,
    MSVM_RETURNCODE_INVALID_PARAMETER = 32773,
    MSVM_RETURNCODE_SYSTEM_IS_IN_USE = 32774,
    MSVM_RETURNCODE_INVALID_STATE_FOR_THIS_OPERATION = 32775,
    MSVM_RETURNCODE_INCORRECT_DATA_TYPE = 32776,
    MSVM_RETURNCODE_SYSTEM_IS_NOT_AVAILABLE = 32777,
    MSVM_RETURNCODE_OUT_OF_MEMORY = 32778,
};

const char *hypervReturnCodeToString(int returnCode);



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Msvm_ComputerSystem
 */

int hypervInvokeMsvmComputerSystemRequestStateChange(virDomainPtr domain,
                                                     int requestedState);

int hypervMsvmComputerSystemEnabledStateToDomainState
      (Msvm_ComputerSystem *computerSystem);

bool hypervIsMsvmComputerSystemActive(Msvm_ComputerSystem *computerSystem,
                                      bool *in_transition);

int hypervMsvmComputerSystemToDomain(virConnectPtr conn,
                                     Msvm_ComputerSystem *computerSystem,
                                     virDomainPtr *domain);

int hypervMsvmComputerSystemFromDomain(virDomainPtr domain,
                                       Msvm_ComputerSystem **computerSystem);



# include "hyperv_wmi.generated.h"

#endif /* __HYPERV_WMI_H__ */
