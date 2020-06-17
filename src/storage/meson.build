storage_driver_backend_sources = [
  'storage_backend.c',
]

storage_driver_sources = [
  'storage_driver.c',
  'storage_util.c',
  storage_driver_backend_sources,
]

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
endif
