storage_driver_backend_sources = [
  'storage_backend.c',
]

storage_driver_sources = [
  'storage_driver.c',
  'storage_util.c',
  storage_driver_backend_sources,
]

driver_source_files += files(storage_driver_sources)
stateful_driver_source_files += files(storage_driver_sources)

storage_backend_fs_sources = [
  'storage_backend_fs.c',
]

storage_backend_disk_sources = [
  'storage_backend_disk.c',
]

storage_helper_disk_sources = [
  'parthelper.c',
]

storage_backend_gluster_sources = [
  'storage_backend_gluster.c',
]

storage_backend_iscsi_sources = [
  'storage_backend_iscsi.c',
]

storage_backend_iscsi_direct_sources = [
  'storage_backend_iscsi_direct.c',
]

storage_lvm_backend_sources = [
  'storage_backend_logical.c',
]

storage_backend_mpath_sources = [
  'storage_backend_mpath.c',
]

storage_backend_rbd_sources = [
  'storage_backend_rbd.c',
]

storage_backend_scsi_sources = [
  'storage_backend_scsi.c',
]

storage_backend_vstorage_sources = [
  'storage_backend_vstorage.c',
]

storage_backend_zfs_sources = [
  'storage_backend_zfs.c',
]

storage_backend_install_dir = libdir / 'libvirt' / 'storage-backend'

if conf.has('WITH_STORAGE')
  storage_driver_impl_lib = static_library(
    'virt_storage_driver_impl',
    [
      storage_driver_sources,
    ],
    dependencies: [
      access_dep,
      blkid_dep,
      secdriver_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
      include_directories('..' / 'storage_file'),
    ],
  )

  virt_modules += {
    'name': 'virt_driver_storage',
    'link_whole': [
      storage_driver_impl_lib,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_modules += {
    'name': 'virt_storage_backend_fs',
    'sources': [
      files(storage_backend_fs_sources),
    ],
    'install_dir': storage_backend_install_dir,
  }

  virt_daemons += {
    'name': 'virtstoraged',
    'c_args': [
      '-DDAEMON_NAME="virtstoraged"',
      '-DMODULE_NAME="storage"',
    ],
  }

  virt_daemon_confs += {
    'name': 'virtstoraged',
  }

  virt_daemon_units += {
    'service': 'virtstoraged',
    'name': 'storage',
    'service_extra_in': [
      files('virtstoraged.service.extra.in'),
    ],
    'socket_extra_in': [
      files('virtstoraged.socket.extra.in'),
    ],
  }

  openrc_init_files += {
    'name': 'virtstoraged',
    'in_file': files('virtstoraged.init.in'),
  }

  virt_install_dirs += [
    confdir / 'storage',
    confdir / 'storage' / 'autostart',
    runstatedir / 'libvirt' / 'storage',
  ]
endif

if conf.has('WITH_STORAGE_DISK')
  virt_modules += {
    'name': 'virt_storage_backend_disk',
    'sources': [
      files(storage_backend_disk_sources),
    ],
    'install_dir': storage_backend_install_dir,
  }

  virt_helpers += {
    'name': 'libvirt_parthelper',
    'sources': [
      files(storage_helper_disk_sources),
      dtrace_gen_objects,
    ],
    'deps': [
      libparted_dep,
    ],
  }
endif

if conf.has('WITH_STORAGE_GLUSTER')
  virt_modules += {
    'name': 'virt_storage_backend_gluster',
    'sources': [
      files(storage_backend_gluster_sources),
    ],
    'deps': [
      glusterfs_dep,
    ],
    'include': [
      include_directories('..' / 'storage_file'),
    ],
    'install_dir': storage_backend_install_dir,
  }
endif

if conf.has('WITH_STORAGE_ISCSI')
  virt_modules += {
    'name': 'virt_storage_backend_iscsi',
    'sources': [
      files(storage_backend_iscsi_sources),
    ],
    'install_dir': storage_backend_install_dir,
  }
endif

if conf.has('WITH_STORAGE_ISCSI_DIRECT')
  virt_modules += {
    'name': 'virt_storage_backend_iscsi-direct',
    'sources': [
      files(storage_backend_iscsi_direct_sources),
    ],
    'deps': [
      libiscsi_dep
    ],
    'install_dir': storage_backend_install_dir,
  }
endif

if conf.has('WITH_STORAGE_LVM')
  virt_modules += {
    'name': 'virt_storage_backend_logical',
    'sources': [
      files(storage_lvm_backend_sources),
    ],
    'install_dir': storage_backend_install_dir,
  }
endif

if conf.has('WITH_STORAGE_MPATH')
  virt_modules += {
    'name': 'virt_storage_backend_mpath',
    'sources': [
      files(storage_backend_mpath_sources),
    ],
    'deps': [
      devmapper_dep
    ],
    'install_dir': storage_backend_install_dir,
  }
endif

if conf.has('WITH_STORAGE_RBD')
  virt_modules += {
    'name': 'virt_storage_backend_rbd',
    'sources': [
      files(storage_backend_rbd_sources),
    ],
    'deps': [
      rbd_dep
    ],
    'install_dir': storage_backend_install_dir,
  }
endif

if conf.has('WITH_STORAGE_SCSI')
  virt_modules += {
    'name': 'virt_storage_backend_scsi',
    'sources': [
      files(storage_backend_scsi_sources),
    ],
    'install_dir': storage_backend_install_dir,
  }
endif

if conf.has('WITH_STORAGE_VSTORAGE')
  virt_modules += {
    'name': 'virt_storage_backend_vstorage',
    'sources': [
      files(storage_backend_vstorage_sources),
    ],
    'install_dir': storage_backend_install_dir,
  }
endif

if conf.has('WITH_STORAGE_ZFS')
  virt_modules += {
    'name': 'virt_storage_backend_zfs',
    'sources': [
      files(storage_backend_zfs_sources),
    ],
    'install_dir': storage_backend_install_dir,
  }
endif

storage_inc_dir = include_directories('.')
