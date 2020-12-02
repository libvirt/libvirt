stoarge_file_fs_sources = [
  'storage_file_backend_fs.c',
]

storage_file_gluster_sources = [
  'storage_file_backend_gluster.c',
]

storage_file_install_dir = libdir / 'libvirt' / 'storage-file'

if conf.has('WITH_STORAGE')
  virt_modules += {
    'name': 'virt_storage_file_fs',
    'sources': [
      files(stoarge_file_fs_sources),
    ],
    'include': [
      storage_inc_dir,
    ],
    'install_dir': storage_file_install_dir,
  }
endif

if conf.has('WITH_STORAGE_GLUSTER')
  virt_modules += {
    'name': 'virt_storage_file_gluster',
    'sources': [
      files(storage_file_gluster_sources),
    ],
    'include': [
      storage_inc_dir,
    ],
    'deps': [
      glusterfs_dep,
    ],
    'install_dir': storage_file_install_dir,
  }
endif
