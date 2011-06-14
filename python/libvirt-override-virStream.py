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

    def recv(self, nbytes):
        """Write a series of bytes to the stream. This method may
        block the calling application for an arbitrary amount
        of time.

        Errors are not guaranteed to be reported synchronously
        with the call, but may instead be delayed until a
        subsequent call.

        On success, the received data is returned. On failure, an
        exception is raised. If the stream is a NONBLOCK stream and
        the request would block, integer -2 is returned.
        """
        ret = libvirtmod.virStreamRecv(self._o, nbytes)
        if ret == None: raise libvirtError ('virStreamRecv() failed')
        return ret

    def send(self, data):
        """Write a series of bytes to the stream. This method may
        block the calling application for an arbitrary amount
        of time. Once an application has finished sending data
        it should call virStreamFinish to wait for successful
        confirmation from the driver, or detect any error

        This method may not be used if a stream source has been
        registered

        Errors are not guaranteed to be reported synchronously
        with the call, but may instead be delayed until a
        subsequent call.
        """
        ret = libvirtmod.virStreamSend(self._o, data, len(data))
        if ret == -1: raise libvirtError ('virStreamSend() failed')
        return ret
