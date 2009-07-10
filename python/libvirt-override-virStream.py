    def __del__(self):
        try:
            if self.cb:
                libvirtmod.virStreamEventRemoveCallback(self._o)
        except AttributeError:
           pass

        if self._o != None:
            libvirtmod.virStreamFree(self._o)
        self._o = None

    def eventAddCallback(self, cb, opaque):
        """ """
        try:
            self.cb = cb
            self.opaque = opaque
            ret = libvirtmod.virStreamEventAddCallback(self._o, self)
            if ret == -1: raise libvirtError ('virStreamEventAddCallback() failed', conn=self._conn)
        except AttributeError:
            pass
