    def listAllVolumes(self, flags=0):
        """List all storage volumes and returns a list of storage volume objects"""
        ret = libvirtmod.virStoragePoolListAllVolumes(self._o, flags)
        if ret is None:
            raise libvirtError("virStoragePoolListAllVolumes() failed", conn=self)

        retlist = list()
        for volptr in ret:
            retlist.append(virStorageVol(self, _obj=volptr))

        return retlist
