    def listAllSnapshots(self, flags):
        """List all snapshots and returns a list of snapshot objects"""
        ret = libvirtmod.virDomainListAllSnapshots(self._o, flags)
        if ret is None:
            raise libvirtError("virDomainListAllSnapshots() failed", conn=self)

        retlist = list()
        for snapptr in ret:
            retlist.append(virDomainSnapshot(self, _obj=snapptr))

        return retlist
