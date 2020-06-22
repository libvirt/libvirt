vz_driver_sources = [
  'vz_driver.c',
  'vz_utils.c',
  'vz_sdk.c',
]

if conf.has('WITH_VZ')
  vz_driver_impl = static_library(
    'virt_driver_vz_impl',
    [
      vz_driver_sources,
    ],
    dependencies: [
      access_dep,
      libnl_dep,
      parallels_sdk_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_vz',
    'link_whole': [
      vz_driver_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }
endif
