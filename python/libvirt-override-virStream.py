    def __del__(self):
        try:
            if self.cb:
                libvirtmod.virStreamEventRemoveCallback(self._o)
        except AttributeError:
           pass

        if self._o != None:
            libvirtmod.virStreamFree(self._o)
        self._o = None

    def _dispatchStreamEventCallback(self, events, cbData):
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

    def recvAll(self, handler, opaque):
        """Receive the entire data stream, sending the data to the
        requested data sink. This is simply a convenient alternative
        to virStreamRecv, for apps that do blocking-I/o.

        A hypothetical handler function looks like:

            def handler(stream, # virStream instance
                        buf,    # string containing received data
                        opaque): # extra data passed to recvAll as opaque
                fd = opaque
                return os.write(fd, buf)
        """
        while True:
            got = self.recv(1024*64)
            if got == -2:
                raise libvirtError("cannot use recvAll with "
                                   "nonblocking stream")
            if len(got) == 0:
                break

            try:
                ret = handler(self, got, opaque)
                if type(ret) is int and ret < 0:
                    raise RuntimeError("recvAll handler returned %d" % ret)
            except Exception, e:
                try:
                    self.abort()
                except:
                    pass
                raise e

    def sendAll(self, handler, opaque):
        """
        Send the entire data stream, reading the data from the
        requested data source. This is simply a convenient alternative
        to virStreamSend, for apps that do blocking-I/o.

        A hypothetical handler function looks like:

            def handler(stream, # virStream instance
                        nbytes, # int amt of data to read
                        opaque): # extra data passed to recvAll as opaque
                fd = opaque
                return os.read(fd, nbytes)
        """
        while True:
            try:
                got = handler(self, 1024*64, opaque)
            except:
                try:
                    self.abort()
                except:
                    pass
                raise e

            if got == "":
                break

            ret = self.send(got)
            if ret == -2:
                raise libvirtError("cannot use sendAll with "
                                   "nonblocking stream")

    def recv(self, nbytes):
        """Reads a series of bytes from the stream. This method may
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
