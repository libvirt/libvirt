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
endif
