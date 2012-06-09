    def listAllChildren(self, flags):
        """List all child snapshots and returns a list of snapshot objects"""
        ret = libvirtmod.virDomainSnapshotListAllChildren(self._o, flags)
        if ret is None:
            raise libvirtError("virDomainSnapshotListAllChildren() failed", conn=self)

        retlist = list()
        for snapptr in ret:
            retlist.append(virDomainSnapshot(self, _obj=snapptr))

        return retlist
