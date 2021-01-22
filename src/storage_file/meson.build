storage_file_sources = [
  'storage_source.c',
  'storage_source_backingstore.c',
  'storage_file_backend.c',
  'storage_file_probe.c',
]

stoarge_file_fs_sources = [
  'storage_file_backend_fs.c',
]

storage_file_gluster_sources = [
  'storage_file_backend_gluster.c',
]

storage_file_install_dir = libdir / 'libvirt' / 'storage-file'

virt_storage_file_lib = static_library(
  'virt_storage_file',
  [
    storage_file_sources,
  ],
  dependencies: [
    src_dep,
  ],
  include_directories: [
    conf_inc_dir,
  ],
)

libvirt_libs += virt_storage_file_lib

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

storage_file_inc_dir = include_directories('.')
