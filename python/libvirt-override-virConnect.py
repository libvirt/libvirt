    def __del__(self):
        try:
           for cb,opaque in self.domainEventCallbacks.items():
               del self.domainEventCallbacks[cb]
           del self.domainEventCallbacks
           libvirtmod.virConnectDomainEventDeregister(self._o, self)
        except AttributeError:
           pass

        if self._o != None:
            libvirtmod.virConnectClose(self._o)
        self._o = None

    def domainEventDeregister(self, cb):
        """Removes a Domain Event Callback. De-registering for a
           domain callback will disable delivery of this event type """
        try:
            del self.domainEventCallbacks[cb]
            if len(self.domainEventCallbacks) == 0:
                del self.domainEventCallbacks
                ret = libvirtmod.virConnectDomainEventDeregister(self._o, self)
                if ret == -1: raise libvirtError ('virConnectDomainEventDeregister() failed', conn=self)
        except AttributeError:
            pass

    def domainEventRegister(self, cb, opaque):
        """Adds a Domain Event Callback. Registering for a domain
           callback will enable delivery of the events """
        try:
            self.domainEventCallbacks[cb] = opaque
        except AttributeError:
            self.domainEventCallbacks = {cb:opaque}
            ret = libvirtmod.virConnectDomainEventRegister(self._o, self)
            if ret == -1: raise libvirtError ('virConnectDomainEventRegister() failed', conn=self)

    def _dispatchDomainEventCallbacks(self, dom, event, detail):
        """Dispatches events to python user domain event callbacks
        """
        try:
            for cb,opaque in self.domainEventCallbacks.items():
                cb(self,dom,event,detail,opaque)
            return 0
        except AttributeError:
            pass

    def _dispatchDomainEventLifecycleCallback(self, dom, event, detail, cbData):
        """Dispatches events to python user domain lifecycle event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), event, detail, opaque)
        return 0

    def _dispatchDomainEventGenericCallback(self, dom, cbData):
        """Dispatches events to python user domain generic event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), opaque)
        return 0

    def _dispatchDomainEventRTCChangeCallback(self, dom, offset, cbData):
        """Dispatches events to python user domain RTC change event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), offset ,opaque)
        return 0

    def _dispatchDomainEventWatchdogCallback(self, dom, action, cbData):
        """Dispatches events to python user domain watchdog event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), action, opaque)
        return 0

    def _dispatchDomainEventIOErrorCallback(self, dom, srcPath, devAlias,
                                            action, cbData):
        """Dispatches events to python user domain IO error event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), srcPath, devAlias, action, opaque)
        return 0

    def _dispatchDomainEventIOErrorReasonCallback(self, dom, srcPath,
                                                  devAlias, action, reason,
                                                  cbData):
        """Dispatches events to python user domain IO error event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), srcPath, devAlias, action,
           reason, opaque)
        return 0

    def _dispatchDomainEventGraphicsCallback(self, dom, phase, localAddr,
                                            remoteAddr, authScheme, subject,
                                            cbData):
        """Dispatches events to python user domain graphics event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), phase, localAddr, remoteAddr,
           authScheme, subject, opaque)
        return 0

    def dispatchDomainEventBlockPullCallback(self, dom, path, type, status, cbData):
        """Dispatches events to python user domain blockJob event callbacks
        """
        try:
            cb = cbData["cb"]
            opaque = cbData["opaque"]

            cb(self, virDomain(self, _obj=dom), path, type, status, opaque)
            return 0
        except AttributeError:
            pass

    def _dispatchDomainEventDiskChangeCallback(self, dom, oldSrcPath, newSrcPath, devAlias, reason, cbData):
        """Dispatches event to python user domain diskChange event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), oldSrcPath, newSrcPath, devAlias, reason, opaque)
        return 0

    def _dispatchDomainEventTrayChangeCallback(self, dom, devAlias, reason, cbData):
        """Dispatches event to python user domain trayChange event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), devAlias, reason, opaque)
        return 0

    def _dispatchDomainEventPMWakeupCallback(self, dom, reason, cbData):
        """Dispatches event to python user domain pmwakeup event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), reason, opaque)
        return 0

    def _dispatchDomainEventPMSuspendCallback(self, dom, reason, cbData):
        """Dispatches event to python user domain pmsuspend event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), reason, opaque)
        return 0

    def _dispatchDomainEventBalloonChangeCallback(self, dom, actual, cbData):
        """Dispatches events to python user domain balloon change event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), actual, opaque)
        return 0

    def _dispatchDomainEventPMSuspendDiskCallback(self, dom, reason, cbData):
        """Dispatches event to python user domain pmsuspend-disk event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), reason, opaque)
        return 0

    def _dispatchDomainEventDeviceRemovedCallback(self, dom, devAlias, cbData):
        """Dispatches event to python user domain device removed event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, virDomain(self, _obj=dom), devAlias, opaque)
        return 0

    def domainEventDeregisterAny(self, callbackID):
        """Removes a Domain Event Callback. De-registering for a
           domain callback will disable delivery of this event type """
        try:
            ret = libvirtmod.virConnectDomainEventDeregisterAny(self._o, callbackID)
            if ret == -1: raise libvirtError ('virConnectDomainEventDeregisterAny() failed', conn=self)
            del self.domainEventCallbackID[callbackID]
        except AttributeError:
            pass

    def domainEventRegisterAny(self, dom, eventID, cb, opaque):
        """Adds a Domain Event Callback. Registering for a domain
           callback will enable delivery of the events """
        if not hasattr(self, 'domainEventCallbackID'):
            self.domainEventCallbackID = {}
        cbData = { "cb": cb, "conn": self, "opaque": opaque }
        if dom is None:
            ret = libvirtmod.virConnectDomainEventRegisterAny(self._o, None, eventID, cbData)
        else:
            ret = libvirtmod.virConnectDomainEventRegisterAny(self._o, dom._o, eventID, cbData)
        if ret == -1:
            raise libvirtError ('virConnectDomainEventRegisterAny() failed', conn=self)
        self.domainEventCallbackID[ret] = opaque
        return ret

    def listAllDomains(self, flags=0):
        """List all domains and returns a list of domain objects"""
        ret = libvirtmod.virConnectListAllDomains(self._o, flags)
        if ret is None:
            raise libvirtError("virConnectListAllDomains() failed", conn=self)

        retlist = list()
        for domptr in ret:
            retlist.append(virDomain(self, _obj=domptr))

        return retlist

    def listAllStoragePools(self, flags=0):
        """Returns a list of storage pool objects"""
        ret = libvirtmod.virConnectListAllStoragePools(self._o, flags)
        if ret is None:
            raise libvirtError("virConnectListAllStoragePools() failed", conn=self)

        retlist = list()
        for poolptr in ret:
            retlist.append(virStoragePool(self, _obj=poolptr))

        return retlist

    def listAllNetworks(self, flags=0):
        """Returns a list of network objects"""
        ret = libvirtmod.virConnectListAllNetworks(self._o, flags)
        if ret is None:
            raise libvirtError("virConnectListAllNetworks() failed", conn=self)

        retlist = list()
        for netptr in ret:
            retlist.append(virNetwork(self, _obj=netptr))

        return retlist

    def listAllInterfaces(self, flags=0):
        """Returns a list of interface objects"""
        ret = libvirtmod.virConnectListAllInterfaces(self._o, flags)
        if ret is None:
            raise libvirtError("virConnectListAllInterfaces() failed", conn=self)

        retlist = list()
        for ifaceptr in ret:
            retlist.append(virInterface(self, _obj=ifaceptr))

        return retlist

    def listAllDevices(self, flags=0):
        """Returns a list of host node device objects"""
        ret = libvirtmod.virConnectListAllNodeDevices(self._o, flags)
        if ret is None:
            raise libvirtError("virConnectListAllNodeDevices() failed", conn=self)

        retlist = list()
        for devptr in ret:
            retlist.append(virNodeDevice(self, _obj=devptr))

        return retlist

    def listAllNWFilters(self, flags=0):
        """Returns a list of network filter objects"""
        ret = libvirtmod.virConnectListAllNWFilters(self._o, flags)
        if ret is None:
            raise libvirtError("virConnectListAllNWFilters() failed", conn=self)

        retlist = list()
        for filter_ptr in ret:
            retlist.append(virNWFilter(self, _obj=filter_ptr))

        return retlist

    def listAllSecrets(self, flags=0):
        """Returns a list of secret objects"""
        ret = libvirtmod.virConnectListAllSecrets(self._o, flags)
        if ret is None:
            raise libvirtError("virConnectListAllSecrets() failed", conn=self)

        retlist = list()
        for secret_ptr in ret:
            retlist.append(virSecret(self, _obj=secret_ptr))

        return retlist

    def _dispatchCloseCallback(self, reason, cbData):
        """Dispatches events to python user close callback"""
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, reason, opaque)
        return 0


    def unregisterCloseCallback(self):
        """Removes a close event callback"""
        ret = libvirtmod.virConnectUnregisterCloseCallback(self._o)
        if ret == -1: raise libvirtError ('virConnectUnregisterCloseCallback() failed', conn=self)

    def registerCloseCallback(self, cb, opaque):
        """Adds a close event callback, providing a notification
         when a connection fails / closes"""
        cbData = { "cb": cb, "conn": self, "opaque": opaque }
        ret = libvirtmod.virConnectRegisterCloseCallback(self._o, cbData)
        if ret == -1:
            raise libvirtError ('virConnectRegisterCloseCallback() failed', conn=self)
        return ret

    def createXMLWithFiles(self, xmlDesc, files, flags=0):
        """Launch a new guest domain, based on an XML description similar
        to the one returned by virDomainGetXMLDesc()
        This function may require privileged access to the hypervisor.
        The domain is not persistent, so its definition will disappear when it
        is destroyed, or if the host is restarted (see virDomainDefineXML() to
        define persistent domains).

        @files provides an array of file descriptors which will be
        made available to the 'init' process of the guest. The file
        handles exposed to the guest will be renumbered to start
        from 3 (ie immediately following stderr). This is only
        supported for guests which use container based virtualization
        technology.

        If the VIR_DOMAIN_START_PAUSED flag is set, the guest domain
        will be started, but its CPUs will remain paused. The CPUs
        can later be manually started using virDomainResume.

        If the VIR_DOMAIN_START_AUTODESTROY flag is set, the guest
        domain will be automatically destroyed when the virConnectPtr
        object is finally released. This will also happen if the
        client application crashes / loses its connection to the
        libvirtd daemon. Any domains marked for auto destroy will
        block attempts at migration, save-to-file, or snapshots. """
        ret = libvirtmod.virDomainCreateXMLWithFiles(self._o, xmlDesc, files, flags)
        if ret is None:raise libvirtError('virDomainCreateXMLWithFiles() failed', conn=self)
        __tmp = virDomain(self,_obj=ret)
        return __tmp
