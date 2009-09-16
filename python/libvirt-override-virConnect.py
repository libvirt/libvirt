    def __del__(self):
        try:
           for cb,opaque in self.domainEventCallbacks.items():
               del self.domainEventCallbacks[cb]
           self.domainEventCallbacks = None
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

    def dispatchDomainEventCallbacks(self, dom, event, detail):
        """Dispatches events to python user domain event callbacks
        """
        try:
            for cb,opaque in self.domainEventCallbacks.items():
                cb(self,dom,event,detail,opaque)
            return 0
        except AttributeError:
            pass
