    def getConnect(self):
        """Get the connection that owns the domain that a snapshot was created for"""
        return self.connect()

    def getDomain(self):
        """Get the domain that a snapshot was created for"""
        return self.domain()

    def listAllChildren(self, flags=0):
        """List all child snapshots and returns a list of snapshot objects"""
        ret = libvirtmod.virDomainSnapshotListAllChildren(self._o, flags)
        if ret is None:
            raise libvirtError("virDomainSnapshotListAllChildren() failed", conn=self)

        retlist = list()
        for snapptr in ret:
            retlist.append(virDomainSnapshot(self, _obj=snapptr))

        return retlist
