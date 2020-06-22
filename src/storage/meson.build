storage_driver_backend_sources = [
  'storage_backend.c',
]

storage_driver_sources = [
  'storage_driver.c',
  'storage_util.c',
  storage_driver_backend_sources,
]

storage_backend_fs_sources = [
  'storage_backend_fs.c',
]

stoarge_file_fs_sources = [
  'storage_file_fs.c',
]

storage_backend_disk_sources = [
  'storage_backend_disk.c',
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

storage_backend_scsi_sources = [
  'storage_backend_scsi.c',
]

storage_backend_install_dir = libdir / 'libvirt' / 'storage-backend'
storage_file_install_dir = libdir / 'libvirt' / 'storage-file'

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

  virt_modules += {
    'name': 'virt_storage_file_fs',
    'sources': [
      files(stoarge_file_fs_sources),
    ],
    'install_dir': storage_file_install_dir,
  }
endif

if conf.has('WITH_STORAGE_DISK')
  virt_modules += {
    'name': 'virt_storage_backend_disk',
    'sources': [
      files(storage_backend_disk_sources),
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

if conf.has('WITH_STORAGE_SCSI')
  virt_modules += {
    'name': 'virt_storage_backend_scsi',
    'sources': [
      files(storage_backend_scsi_sources),
    ],
    'install_dir': storage_backend_install_dir,
  }
endif
