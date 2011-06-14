    def __del__(self):
        try:
            if self.cb:
                libvirtmod.virStreamEventRemoveCallback(self._o)
        except AttributeError:
           pass

        if self._o != None:
            libvirtmod.virStreamFree(self._o)
        self._o = None

    def dispatchStreamEventCallback(self, events, cbData):
        """
        Dispatches events to python user's stream event callbacks
        """
        cb = cbData["cb"]
        opaque = cbData["opaque"]

        cb(self, events, opaque)
        return 0

    def eventAddCallback(self, events, cb, opaque):
        self.cb = cb
        cbData = {"stream": self, "cb" : cb, "opaque" : opaque}
        ret = libvirtmod.virStreamEventAddCallback(self._o, events, cbData)
        if ret == -1: raise libvirtError ('virStreamEventAddCallback() failed')
