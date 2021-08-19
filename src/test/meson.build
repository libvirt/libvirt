test_driver_sources = [
  'test_driver.c',
]

test_driver_assets = [
  'test-screenshot.png',
]

if conf.has('WITH_TEST')
  test_lib = static_library(
    'virt_test',
    [
      test_driver_sources,
    ],
    dependencies: [
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
      hypervisor_inc_dir,
    ],
  )

  libvirt_libs += test_lib

  install_data(test_driver_assets, install_dir: pkgdatadir)
endif
